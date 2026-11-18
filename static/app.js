document.addEventListener('click',function(e){
  var b=e.target.closest('[data-copy]');
  if(!b)return;
  var t=b.getAttribute('data-copy');
  (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).catch(function(){
    var a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');a.remove();});
  var o=b.getAttribute('title');b.setAttribute('title','Copied');setTimeout(function(){b.setAttribute('title',o||'Copy')},1200);
});
document.addEventListener('submit',function(e){
  var f=e.target;if(f.dataset.confirm&&!confirm(f.dataset.confirm))e.preventDefault();
});
(function(){
  var box=document.getElementById('msgs');if(!box)return;
  var uid=box.dataset.uid,admin=box.dataset.admin==='1',csrf=box.dataset.csrf,last=0;
  function add(m){
    var mine=(admin&&m.sender==='admin')||(!admin&&m.sender==='user');
    var d=document.createElement('div');d.className='bub'+(mine?' mine':'');
    d.appendChild(document.createTextNode(m.body));
    var s=document.createElement('small');s.textContent=m.t;d.appendChild(s);box.appendChild(d);last=m.id;
  }
  function poll(){
    fetch('/chat/poll?uid='+uid+'&after='+last,{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(a){
      if(a.length){a.forEach(add);box.scrollTop=box.scrollHeight}
    }).catch(function(){});
  }
  poll();setInterval(poll,3000);
  document.getElementById('cform').addEventListener('submit',function(e){
    e.preventDefault();var i=document.getElementById('cbody');var v=i.value.trim();if(!v)return;
    var fd=new FormData();fd.append('body',v);fd.append('uid',uid);
    fetch('/chat/send',{method:'POST',body:fd,headers:{'X-CSRF':csrf},credentials:'same-origin'}).then(function(){i.value='';poll()});
  });
})();
