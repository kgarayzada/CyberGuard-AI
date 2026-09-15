import {chromium} from '../frontend/node_modules/playwright-core/index.mjs';
import assert from 'node:assert/strict';
const browser=await chromium.launch({executablePath:'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',headless:true});
try{
 const page=await browser.newPage({viewport:{width:1366,height:768}});await page.goto('http://127.0.0.1:5173/#findings');const all=await(await page.request.get('http://127.0.0.1:5173/api/assessments')).json();const demo=all.find(a=>a.project_name==='CyberGuard Vulnerable Demo');await page.getByLabel('Assessment filter').selectOption(demo.id);await page.waitForTimeout(500);
 await page.getByLabel('scanner filter',{exact:true}).selectOption('Gitleaks');assert.equal(await page.locator('.risk-row').count(),1);await page.getByLabel('Search findings',{exact:true}).fill('nonexistent-pattern-qa');assert.equal(await page.locator('.risk-row').count(),0);await page.getByLabel('Search findings',{exact:true}).fill('');await page.locator('.risk-row').click();await page.getByLabel('Finding status',{exact:true}).selectOption('ACCEPTED');await page.waitForTimeout(400);await page.reload();await page.getByLabel('Finding status',{exact:true}).waitFor();assert.equal(await page.getByLabel('Finding status',{exact:true}).inputValue(),'ACCEPTED');
 const failed=all.find(a=>a.project_name==='All unavailable QA');await page.goto('http://127.0.0.1:5173/#assessments/'+failed.id);await page.getByText('Assessment could not be completed. No findings were fabricated.').waitFor();assert.ok(await page.getByText('Unavailable',{exact:true}).count()>=2);console.log('PASS: scanner filter, search, persisted triage status, and failed coverage UI.');
}finally{await browser.close()}

