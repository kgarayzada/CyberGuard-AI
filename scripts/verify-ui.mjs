import {chromium} from '../frontend/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';
import path from 'node:path';
import assert from 'node:assert/strict';
const root=process.cwd();
const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true,args:['--no-first-run']});
const page=await browser.newPage({viewport:{width:1440,height:900}});const errors=[];
page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});
try{
 await page.goto('http://127.0.0.1:5173');await page.getByRole('heading',{name:'Your security posture. At a glance.'}).waitFor();
 const a=await (await page.request.get('http://127.0.0.1:5173/api/assessments')).json();
 const demo=a.find(x=>x.project_name==='CyberGuard Vulnerable Demo');
 for(const width of [1440,1366,1024,390]){
  await page.setViewportSize({width,height:900});
  const routes=['overview','upload','assessments','findings','reports'];
  if(demo){const detail=await (await page.request.get('http://127.0.0.1:5173/api/assessments/'+demo.id)).json();routes.push('assessments/'+demo.id,'reports/'+demo.id);if(detail.findings.length)routes.push('findings/'+detail.findings[0].id)}
  for(const route of routes){await page.goto('http://127.0.0.1:5173/#'+route);await page.waitForTimeout(500);assert.equal(await page.locator('body').evaluate(el=>el.scrollWidth>innerWidth+2),false,route+' overflow '+width);}
 }
 await page.setViewportSize({width:1440,height:900});await page.goto('http://127.0.0.1:5173/#upload');await page.getByLabel('Source ZIP').setInputFiles(path.join(root,'demo/cyberguard-vulnerable-demo.zip'));await page.locator('input[name=project_name]').fill('Browser upload QA');await page.locator('input[name=authorized]').check();await page.getByRole('button',{name:'START ASSESSMENT',exact:true}).click();await page.waitForURL(/assessments\//);await page.getByRole('button',{name:'VIEW SECURITY REPORT'}).waitFor({timeout:240000});await page.getByRole('button',{name:'VIEW SECURITY REPORT'}).click();await page.getByRole('heading',{name:'Executive summary'}).waitFor();
 assert.deepEqual(errors,[]);fs.mkdirSync('.tooling/qa',{recursive:true});await page.screenshot({path:'.tooling/qa/report.png',fullPage:true});console.log('PASS: browser upload, scanner completion, report; responsive routes at 1440/1366/1024/390; zero console/runtime errors.');
}finally{await browser.close()}
