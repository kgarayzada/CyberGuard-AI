import {chromium} from '../frontend/node_modules/playwright-core/index.mjs';
import assert from 'node:assert/strict';
const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
try{
 const page=await browser.newPage({viewport:{width:1366,height:768}});const errors=[];page.on('pageerror',e=>errors.push(e.message));page.on('console',m=>{if(m.type()==='error')errors.push(m.text())});
 await page.goto('http://127.0.0.1:5173');await page.getByRole('heading',{name:'No assessments yet',exact:true}).waitFor();assert.equal((await (await page.request.get('http://127.0.0.1:5173/api/findings')).json()).length,0);
 await page.getByRole('button',{name:'UPLOAD SOURCE CODE',exact:true}).first().click();await page.getByLabel('Source ZIP').waitFor();await page.screenshot({path:'.tooling/qa/empty-upload.png'});await page.goto('http://127.0.0.1:5173/#overview');await page.getByRole('heading',{name:'No assessments yet',exact:true}).waitFor();await page.screenshot({path:'.tooling/qa/empty-dashboard.png'});assert.deepEqual(errors,[]);console.log('PASS: reset empty dashboard, upload page, zero findings, no browser errors.');
}finally{await browser.close()}

