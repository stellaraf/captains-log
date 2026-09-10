import {chromium} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import {privateDir,baseURL} from './local-auth.mjs';
const browser=await chromium.launch({headless:true,channel:'chrome'});
try {
 const context=await browser.newContext({storageState:path.join(privateDir,'browser-state.json'),viewport:{width:1560,height:1000}});
 const page=await context.newPage();await page.goto(`${baseURL}/logs/traffic`);await page.getByLabel('Filter query').waitFor();
 const results=[];
 for(const theme of ['light','dark']) {
   await page.getByLabel('Theme').selectOption(theme);await page.getByLabel('Theme').isEnabled();
   await page.waitForFunction(t=>document.documentElement.dataset.theme===t,theme);
   const colors=await page.evaluate(()=>{const pairs=[];const selectors=['.page-head h1','.breadcrumbs','.nav-link.active','.nav-link:not(.active)','.nav-overline','.timestamp','.ip-value','.cell-filter','.query-help','.query-bar .primary','.table-footer','.ingest-strip','.workspace-foot'];for(const selector of selectors){const el=document.querySelector(selector);if(!el)continue;let bg=el;while(bg&&getComputedStyle(bg).backgroundColor==='rgba(0, 0, 0, 0)')bg=bg.parentElement;pairs.push({selector,foreground:getComputedStyle(el).color,background:bg?getComputedStyle(bg).backgroundColor:getComputedStyle(document.documentElement).backgroundColor});}return pairs});
   const luminance=color=>{const rgb=color.match(/[\d.]+/g).slice(0,3).map(Number).map(v=>v/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return rgb.reduce((s,v,i)=>s+v*[.2126,.7152,.0722][i],0)};
   for(const c of colors){const l=[luminance(c.foreground),luminance(c.background)].sort((a,b)=>b-a);results.push({theme,...c,ratio:+((l[0]+.05)/(l[1]+.05)).toFixed(2)})}
 }
 fs.writeFileSync(path.join(privateDir,'contrast-review.json'),JSON.stringify(results,null,2),{mode:0o600});
 const failures=results.filter(r=>r.ratio<4.5);console.log(JSON.stringify({pairs:results.length,minimum:Math.min(...results.map(r=>r.ratio)),failures}));if(failures.length)process.exitCode=1;
}finally{await browser.close()}
