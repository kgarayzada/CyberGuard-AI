import {chromium} from '../frontend/node_modules/playwright-core/index.mjs';
import path from 'node:path';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const context=await chromium.launchPersistentContext(path.join(root,'.tooling','browser-profile'),{channel:'chrome',headless:true,viewport:{width:1440,height:900}});
const page=context.pages()[0];
try{
 await page.goto('http://127.0.0.1:5173');await page.locator('.score-ring').waitFor();assert.equal(await page.locator('.score-ring strong').innerText(),'58');assert.match(await page.locator('.score-bottom').innerText(),/Previous 51/);assert.equal(await page.locator('.score-ring').evaluate(e=>e.style.getPropertyValue('--score')),'43.5%');
 await page.goto('http://127.0.0.1:5173/#findings/CG-F001');await page.locator('.steps').scrollIntoViewIfNeeded();assert(await page.evaluate(()=>scrollY)>100);await page.locator('nav a[href="#paths"]').click();await page.getByRole('heading',{name:'See the chain. Break the risk.'}).waitFor();assert.equal(await page.evaluate(()=>scrollY),0);
 const state=await (await page.request.get('http://127.0.0.1:5173/api/state')).json();assert.equal(state.scans.length,4);assert.equal(state.summary.open,10);assert.equal(state.summary.resolved,1);assert.equal(state.summary.previous,51);assert.equal(state.paths.length,2);const reports=await (await page.request.get('http://127.0.0.1:5173/api/reports')).json();assert.equal(reports.length,0);
 console.log('PASS: Final running build, correct gauge, clean 58/100 baseline, scroll reset on navigation, four scans and no generated test reports.');
}finally{await context.close()}
