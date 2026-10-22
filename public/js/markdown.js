"use strict";

/*
 Minimal, safe Markdown -> HTML for research reports.
 Supports: # / ## / ### headings, tables, "- " lists, ---, **bold**, `code`,
 _italic_, [text](https://link). Everything is HTML-escaped first; only
 http(s) links survive (safeUrl). Reuses escapeHTML/safeUrl from utils.js.
*/

function mdInline(raw){
  const re = /\[([^\]]+)\]\((https?:\/\/[^)\s]+)\)|`([^`]+)`|\*\*([^*]+)\*\*|(?<![\w])_([^_]+)_(?![\w])/g;
  let out = "";
  let last = 0;
  for(const m of raw.matchAll(re)){
    out += escapeHTML(raw.slice(last, m.index));
    if(m[2]){
      const href = safeUrl(m[2]);
      out += href
        ? `<a href="${escapeHTML(href)}" target="_blank" rel="noopener noreferrer">${escapeHTML(m[1])}</a>`
        : escapeHTML(m[0]);
    }else if(m[3] !== undefined){
      out += `<code class="ltr">${escapeHTML(m[3])}</code>`;
    }else if(m[4] !== undefined){
      out += `<strong>${escapeHTML(m[4])}</strong>`;
    }else{
      out += `<em>${escapeHTML(m[5])}</em>`;
    }
    last = m.index + m[0].length;
  }
  return out + escapeHTML(raw.slice(last));
}

function mdCells(line){
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map(c => c.trim());
}

function renderMarkdown(markdown){
  const lines = String(markdown ?? "").split("\n");
  const html = [];
  let para = [];
  let list = null;

  const flushPara = () => {
    if(para.length){ html.push("<p>" + para.map(mdInline).join("<br>") + "</p>"); para = []; }
  };
  const flushList = () => {
    if(list){ html.push("<ul>" + list.map(i => "<li>" + mdInline(i) + "</li>").join("") + "</ul>"); list = null; }
  };

  for(let i = 0; i < lines.length; i++){
    const line = lines[i];
    const heading = /^(#{1,3})\s+(.+)$/.exec(line);
    const item = /^\s*-\s+(.+)$/.exec(line);

    if(!line.trim()){ flushPara(); flushList(); continue; }

    if(heading){
      flushPara(); flushList();
      const level = heading[1].length;
      html.push(`<h${level}>${mdInline(heading[2])}</h${level}>`);
    }else if(/^---+\s*$/.test(line)){
      flushPara(); flushList();
      html.push("<hr>");
    }else if(line.trim().startsWith("|") && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}/.test(lines[i + 1])){
      flushPara(); flushList();
      const head = mdCells(line);
      i += 2;
      const rows = [];
      while(i < lines.length && lines[i].trim().startsWith("|")){ rows.push(mdCells(lines[i])); i++; }
      i--;
      html.push(
        '<div class="tablewrap"><table><thead><tr>' + head.map(c => "<th>" + mdInline(c) + "</th>").join("") +
        "</tr></thead><tbody>" +
        rows.map(r => "<tr>" + r.map(c => "<td>" + mdInline(c) + "</td>").join("") + "</tr>").join("") +
        "</tbody></table></div>"
      );
    }else if(item){
      flushPara();
      (list ||= []).push(item[1]);
    }else{
      flushList();
      para.push(line);
    }
  }
  flushPara(); flushList();
  return html.join("\n");
}
