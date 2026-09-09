// Optional capture only. Run reset-demo.ps1 first for a clean 51 → 58 dashboard.
import {chromium} from '../frontend/node_modules/playwright-core/index.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const executablePath=['C:/Program Files/Google/Chrome/Application/chrome.exe','C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe'].find(p=>fs.existsSync(p));
if(!executablePath)throw new Error('Capture screenshots manually: no installed Chrome or Edge was found.');
const output=path.join(root,'docs','screenshots');fs.mkdirSync(output,{recursive:true});
const context=await chromium.launchPersistentContext(path.join(root,'.tooling','browser-profile'),{executablePath,headless:true,viewport:{width:1440,height:900},deviceScaleFactor:1});
const page=context.pages()[0];
async function visit(route){await page.goto('http://127.0.0.1:5173/#'+route);await page.waitForLoadState('networkidle');await page.locator('main h1').first().waitFor();}
async function capture(name){await page.waitForLoadState('networkidle');const dismiss=page.getByRole('button',{name:'Dismiss message',exact:true});if(await dismiss.count())await dismiss.click();await page.evaluate(()=>document.fonts.ready);await page.screenshot({path:path.join(output,name),animations:'disabled'});}
try {
 await visit('overview');await capture('01-dashboard.png');
 await page.getByRole('button',{name:'START SECURITY SCAN',exact:true}).click();await page.getByText('Assessment complete',{exact:true}).waitFor({timeout:12000});await page.getByRole('button',{name:'View assessment results'}).click();await capture('02-scan-completed.png');
 await visit('findings/CG-F001');await page.locator('.context-score').waitFor();await capture('03-critical-finding.png');
 await visit('analyst');await page.locator('.analyst-prompts>button').first().click();await page.locator('.answer-foot').waitFor();await capture('04-ai-analysis.png');
 await visit('paths');await capture('05-attack-path.png');
 await visit('reports');await page.getByRole('button',{name:'VIEW SECURITY REPORT',exact:true}).click();await page.locator('.security-report').waitFor();await page.evaluate(()=>{const report=document.querySelector('.security-report');window.scrollTo(0,report.getBoundingClientRect().top+window.scrollY-88)});await capture('06-security-report.png');
 console.log('Six presentation screenshots captured. Run reset-demo.ps1 to restore the initial state.');
} finally {await context.close()}
