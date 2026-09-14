"use strict";
const support=require("./module-support");
function create(options){
  options=options||{};const s=options.support||support.create("local-access");
  const call=(args)=>s.run("unknown-home-access.js",args);
  function clean(r){const out=Object.assign({},r);delete out.passphrase;return out;}
  function report(){const r=clean(call(["status"]));r.healthy=(!r.sshEnabled||r.sshRunning)&&(!r.keyServerEnabled||r.keyServerRunning);r.scope="Unjailed, public-key root SSH. Existing independent recovery listeners and keys are not removed.";return r;}
  async function run(action,args){
    args=args||{};
    if(action==="enable"){s.claim();const old=s.state(),r=call(["status"]);if(!old)s.save({desired:{ssh:r.sshEnabled,keyserver:r.keyServerEnabled}});else{for(const key of ["ssh","keyserver"])if(old.desired[key])call([key,"on"]);}call(["start-enabled"]);const now=call(["status"]);s.save({desired:{ssh:now.sshEnabled,keyserver:now.keyServerEnabled},suspended:false});}
    else if(action==="disable"){s.claim();const r=call(["status"]);s.suspend({ssh:r.sshEnabled,keyserver:r.keyServerEnabled});call(["stop-all"]);}
    else if(action==="reconcile"||action==="maintenance"){s.claim();const r=call(["status"]);if(r.sshEnabled&&!r.sshRunning||r.keyServerEnabled&&!r.keyServerRunning)call(["start-enabled"]);}
    else if(action==="setService"){if(!["ssh","keyserver"].includes(args.service)||typeof args.enabled!=="boolean")throw Error("Choose SSH or key server and an enabled value");call([args.service,args.enabled?"on":"off"]);const r=call(["status"]);s.save({desired:{ssh:r.sshEnabled,keyserver:r.keyServerEnabled}});}
    else if(action==="showPairing"){const r=call(["status"]);return {ipAddress:r.ipAddress,user:"root",sshPort:r.sshPort,keyServerPort:r.keyServerPort,keyUrl:r.keyUrl,passphrase:r.passphrase,warning:"Private pairing information. Do not share screenshots or logs of this screen."};}
    else if(!["status","health"].includes(action))throw Error("Unknown local-access action");
    return report();
  }
  return {run};
}
if(require.main===module)support.main(create);module.exports={create};
