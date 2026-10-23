// Local Vercel-style adapter. Never serves server source, secrets or test fixtures.
const http=require('node:http');
const fs=require('node:fs/promises');
const path=require('node:path');
const {pathToFileURL}=require('node:url');
const root=path.join(__dirname,'..');
const routes=new Set(['hint','resolve-username','soc']);
async function serve(req,res,api) {
  res.status=n=>{res.statusCode=n;return res;};
  res.json=value=>{res.setHeader('Content-Type','application/json');res.end(JSON.stringify(value));};
  try {
    const url=new URL(req.url,'http://localhost');
    const route=/^\/api\/([a-z-]+)$/.exec(url.pathname)?.[1];
    if(route && routes.has(route)) {
      let body='';for await(const chunk of req){body+=chunk;if(Buffer.byteLength(body)>65536)return res.status(413).json({error:'Request too large'});}
      try {req.body=body?JSON.parse(body):{};}catch{return res.status(400).json({error:'Invalid JSON'});}
      const handler=api?await api(route):(await import(pathToFileURL(path.join(root,'api',route+'.js')).href)).default;
      return await handler(req,res);
    }
    const file=url.pathname==='/'?'/index.html':url.pathname;
    if(file!=='/index.html' && !/^\/assets\/[a-z-]+\.(js|css)$/.test(file))return res.status(404).json({error:'Not found'});
    const content=await fs.readFile(path.join(root,file));
    res.setHeader('Content-Type',file.endsWith('.html')?'text/html; charset=utf-8':file.endsWith('.css')?'text/css':'text/javascript');res.end(content);
  }catch(error){if(error.code==='ENOENT')return res.status(404).json({error:'Not found'});console.error('Local request failed:',error.message);res.status(500).json({error:'Local server error'});}
}
module.exports={serve};
if(require.main===module)http.createServer((req,res)=>serve(req,res)).listen(Number(process.env.PORT||3000),'127.0.0.1',()=>console.log('CyberGuard development server started'));
