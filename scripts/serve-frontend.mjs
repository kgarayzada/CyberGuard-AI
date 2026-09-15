// Small static presentation server. All browser/API traffic remains on loopback.
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const dist=path.join(root,'frontend','dist');
const mime={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.svg':'image/svg+xml','.png':'image/png','.ico':'image/x-icon'};
const server=http.createServer((req,res)=>{
  if(req.url==='/__cyberguard') {res.writeHead(200,{'Content-Type':'application/json'});res.end(JSON.stringify({service:'cyberguard-frontend',workspace:root}));return;}
  if(req.url?.startsWith('/api/')) {
    const proxy=http.request({hostname:'127.0.0.1',port:8000,path:req.url,method:req.method,headers:{'content-type':req.headers['content-type']||'application/json',...(req.headers.origin?{origin:req.headers.origin}:{}),...(req.headers['content-length']?{'content-length':req.headers['content-length']}:{})},timeout:120000},upstream=>{res.writeHead(upstream.statusCode??502,{'Content-Type':'application/json','Cache-Control':'no-store'});upstream.pipe(res);});
    proxy.on('timeout',()=>proxy.destroy());
    proxy.on('error',()=>{if(!res.headersSent)res.writeHead(503,{'Content-Type':'application/json'});res.end(JSON.stringify({detail:'The local assessment engine is reconnecting. Please retry.'}));});
    req.pipe(proxy);return;
  }
  if(req.method!=='GET'&&req.method!=='HEAD'){res.writeHead(405);res.end();return;}
  let pathname;
  try {pathname=decodeURIComponent(new URL(req.url,'http://127.0.0.1').pathname)}catch{res.writeHead(400);res.end('Invalid path');return;}
  let file=path.resolve(dist,'.'+pathname);
  if(!file.startsWith(dist+path.sep)&&file!==dist){res.writeHead(403);res.end('Unavailable');return;}
  if(file===dist||!path.extname(file))file=path.join(dist,'index.html');
  fs.readFile(file,(error,content)=>{if(error){res.writeHead(404,{'Content-Type':'text/plain'});res.end('This resource is unavailable. Return to CyberGuard home.');return;}res.writeHead(200,{'Content-Type':mime[path.extname(file)]??'application/octet-stream','Cache-Control':'no-cache','X-Content-Type-Options':'nosniff'});res.end(req.method==='HEAD'?undefined:content);});
});
server.listen(5173,'127.0.0.1',()=>console.log('CyberGuard AI frontend: http://127.0.0.1:5173'));
server.on('error',error=>{console.error('Frontend could not start:',error.message);process.exitCode=1;});

