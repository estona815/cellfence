// Original CellFence engine. No formula evaluation or network access.
export function parseCSV(input, delimiter = ',') {
  if (typeof input !== 'string' || new TextEncoder().encode(input).length > 2_000_000) throw Error('Use a CSV smaller than 2 MB.');
  if (![',', ';', '\t'].includes(delimiter)) throw Error('Unsupported delimiter.');
  const text = input.replace(/^\uFEFF/, '');
  if (!text) throw Error('The CSV is empty.');
  const rows = []; let row = [], value = '', state = 'start';
  const cell = () => { row.push(value); value = ''; state = 'start'; if (row.length > 200) throw Error('Maximum 200 columns.'); };
  const end = () => { cell(); rows.push(row); row = []; if (rows.length > 20000) throw Error('Maximum 20,000 rows.'); };
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (state === 'quoted') {
      if (c === '"') { if (text[i + 1] === '"') { value += '"'; i++; } else state = 'closed'; }
      else value += c;
    } else if (c === delimiter) cell();
    else if (c === '\r' || c === '\n') { end(); if (c === '\r' && text[i + 1] === '\n') i++; }
    else if (state === 'closed') throw Error(`Unexpected character after a closing quote at position ${i + 1}.`);
    else if (c === '"') { if (state !== 'start') throw Error(`Unexpected quote at position ${i + 1}.`); state = 'quoted'; }
    else { value += c; state = 'plain'; }
  }
  if (state === 'quoted') throw Error('Unclosed quoted field. Nothing was exported.');
  if (value || row.length || state !== 'start') end();
  if (!rows.length) throw Error('The CSV has no rows.');
  return rows;
}

export function columnName(index) {
  let out = ''; for (let n = index + 1; n > 0; n = Math.floor((n - 1) / 26)) out = String.fromCharCode(65 + (n - 1) % 26) + out;
  return out;
}

export function audit(rows) {
  const findings = [], widths = new Set(rows.map(r => r.length));
  rows.forEach((row, r) => row.forEach((value, c) => {
    const lead = value.replace(/^[\s\uFEFF]+/u, '');
    const trigger = /^[=+\-@＝＋－＠]/u.test(lead);
    const control = /^[\t\r\n]/.test(value);
    if (trigger || control) findings.push({row:r+1,column:c+1,address:columnName(c)+(r+1),value,
      reason: trigger ? 'Formula-like prefix; spreadsheet interpretation varies.' : 'Leading control character; review before spreadsheet import.',
      note: /^-?\d+(\.\d+)?$/.test(lead) ? 'May be an ordinary number. This is a review flag, not a maliciousness verdict.' : ''});
  }));
  return {rows:rows.length,cells:rows.reduce((n,r)=>n+r.length,0),columns:Math.max(...rows.map(r=>r.length)),findings,
    ragged:widths.size>1,policy:'Every exported cell is explicitly typed as text. Values are not evaluated.'};
}

function xml(value) {
  // SpreadsheetML uses _xHHHH_ escapes; protect literal escape-looking input first.
  return value.replace(/_x[0-9a-f]{4}_/gi, m => '_x005F_' + m.slice(1))
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/g, c => '_x' + c.charCodeAt(0).toString(16).padStart(4,'0').toUpperCase() + '_')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/\r/g,'&#13;');
}
const crcTable = Uint32Array.from({length:256},(_,n)=>{for(let j=0;j<8;j++) n=(n&1)?0xedb88320^(n>>>1):n>>>1; return n>>>0;});
function crc32(data) { let n=0xffffffff; for (const b of data) n=crcTable[(n^b)&255]^(n>>>8); return (n^0xffffffff)>>>0; }
function zip(files) {
  const enc=new TextEncoder(), chunks=[], directory=[]; let offset=0;
  const header=(size)=>{const bytes=new Uint8Array(size);return [bytes,new DataView(bytes.buffer)];};
  for (const [name,body] of Object.entries(files)) {
    const path=enc.encode(name), data=enc.encode(body), crc=crc32(data);
    const [h,v]=header(30+path.length); v.setUint32(0,0x04034b50,true);v.setUint16(4,20,true);v.setUint16(12,33,true);
    v.setUint32(14,crc,true);v.setUint32(18,data.length,true);v.setUint32(22,data.length,true);v.setUint16(26,path.length,true);h.set(path,30);
    const [d,w]=header(46+path.length);w.setUint32(0,0x02014b50,true);w.setUint16(4,20,true);w.setUint16(6,20,true);w.setUint16(14,33,true);
    w.setUint32(16,crc,true);w.setUint32(20,data.length,true);w.setUint32(24,data.length,true);w.setUint16(28,path.length,true);w.setUint32(42,offset,true);d.set(path,46);
    chunks.push(h,data);directory.push(d);offset+=h.length+data.length;
  }
  const size=directory.reduce((n,d)=>n+d.length,0),[end,v]=header(22);v.setUint32(0,0x06054b50,true);v.setUint16(8,directory.length,true);v.setUint16(10,directory.length,true);v.setUint32(12,size,true);v.setUint32(16,offset,true);
  const result=new Uint8Array(offset+size+22);let at=0;for(const p of [...chunks,...directory,end]){result.set(p,at);at+=p.length;}return result;
}

export function exportWorkbook(rows) {
  if (!Array.isArray(rows)||!rows.length||rows.length>20000) throw Error('Invalid row count.');
  let size=0;
  rows.forEach(row=>{if(!Array.isArray(row)||row.length>200)throw Error('Invalid column count.');row.forEach(v=>{if(typeof v!=='string'||v.length>32767)throw Error('Each cell must be text with at most 32,767 characters.');if(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\uFFFE\uFFFF]/.test(v)||[...v].some(ch=>ch.codePointAt(0)>=0xD800&&ch.codePointAt(0)<=0xDFFF))throw Error('Unsupported control or invalid Unicode character. Export stopped to avoid changing your data.');size+=v.length;});});
  if(size>2_000_000)throw Error('Workbook input is too large.');
  const ns='http://schemas.openxmlformats.org/spreadsheetml/2006/main';
  const strings=[]; const indices=new Map();
  const indexOf=v=>{if(!indices.has(v)){indices.set(v,strings.length);strings.push(v);}return indices.get(v);};
  const sheet=`<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="${ns}"><sheetData>${rows.map((row,r)=>`<row r="${r+1}">${row.map((v,c)=>`<c r="${columnName(c)}${r+1}" t="s"><v>${indexOf(v)}</v></c>`).join('')}</row>`).join('')}</sheetData></worksheet>`;
  return zip({
    '[Content_Types].xml':'<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>',
    '_rels/.rels':'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
    'xl/workbook.xml':`<workbook xmlns="${ns}" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Text values" sheetId="1" r:id="rId1"/></sheets></workbook>`,
    'xl/_rels/workbook.xml.rels':'<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>',
    'xl/sharedStrings.xml':`<sst xmlns="${ns}" count="${rows.reduce((n,r)=>n+r.length,0)}" uniqueCount="${strings.length}">${strings.map(v=>`<si><t xml:space="preserve">${xml(v)}</t></si>`).join('')}</sst>`,
    'xl/worksheets/sheet1.xml':sheet
  });
}
