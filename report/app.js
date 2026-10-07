// Поведение HTML-отчёта: тема, навигация, счётчики разделов, «Главное», фильтры, поиск, окно «Подробнее».
// Встраивается в report.html. Разметку строит report/build.sh.
(function(){
  var $=function(s,r){return (r||document).querySelector(s)}, $$=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
  var store={get:function(k){try{return localStorage.getItem(k)}catch(e){return null}},set:function(k,v){try{localStorage.setItem(k,v)}catch(e){}}};

  // тема: как в системе → светлая → тёмная
  var root=document.documentElement, tb=$('#theme'), names={auto:'как в системе',light:'светлая',dark:'тёмная'};
  function setTheme(t){ if(t==='auto') root.removeAttribute('data-theme'); else root.setAttribute('data-theme',t);
    tb.dataset.t=t; tb.title='Тема: '+names[t]; store.set('ra-theme',t); }
  setTheme(store.get('ra-theme')||'auto');
  tb.addEventListener('click',function(){ setTheme({auto:'light',light:'dark',dark:'auto'}[tb.dataset.t]); });

  // навигация по модулям
  var nav=$('#nav');
  $$('article.module').forEach(function(m){ var a=document.createElement('a'); a.href='#'+m.id; a.textContent=m.dataset.name; nav.appendChild(a); });

  // счётчики и статус разделов; разделы без проблем свёрнуты, если в модуле есть проблемы
  $$('details.sec').forEach(function(d){
    var c={ok:0,info:0,warn:0,fail:0};
    $$('.row',d).forEach(function(r){ c[r.dataset.s]=(c[r.dataset.s]||0)+1; });
    $('.counts',d).innerHTML=['fail','warn','info','ok'].filter(function(k){return c[k]}).map(function(k){return '<span class="cnt '+k+'">'+c[k]+'</span>'}).join('');
    d.dataset.s=c.fail?'fail':c.warn?'warn':'ok';
  });
  $$('article.module').forEach(function(m){
    if(!$('.row.warn, .row.fail',m)) return;
    $$('details.sec',m).forEach(function(d){ if(d.dataset.s==='ok') d.open=false; });
  });

  // «Главное»: все FAIL и WARN со ссылками на строку
  var box=$('#findings');
  if(box){
    var items=$$('.row.fail').concat($$('.row.warn'));
    if(!items.length){ box.outerHTML='<p class="empty">Замечаний нет — все проверки прошли.</p>'; }
    items.forEach(function(r){
      var a=document.createElement('a'); a.className='finding '+r.dataset.s; a.href='#'+r.id;
      var msg=$('.msg',r), mod=r.closest('article');
      a.innerHTML='<span class="ic"></span><span class="ft"></span><span class="fm"></span>';
      var ft=$('.ft',a);
      if(r.dataset.t){ var c=document.createElement('code'); c.textContent=r.dataset.t; ft.appendChild(c); }
      ft.appendChild(document.createTextNode(msg?msg.textContent:r.textContent));
      $('.fm',a).textContent=mod?mod.dataset.name:'';
      a.addEventListener('click',function(e){ var d=r.closest('details'); if(d) d.open=true;
        if($('template.det',r)){ e.preventDefault(); openDet(r); } });
      box.appendChild(a);
    });
  }

  // фильтр и поиск
  var q=$('#q');
  function apply(){
    var f=document.body.dataset.f, s=(q.value||'').trim().toLowerCase();
    $$('.row').forEach(function(r){ r.classList.toggle('hide', !!s && (r.textContent+' '+detText(r)).toLowerCase().indexOf(s)<0); });
    $$('details.sec').forEach(function(d){
      var vis=$$('.row',d).some(function(r){ if(r.classList.contains('hide')) return false;
        return f==='all'||(f==='issues'&&/warn|fail/.test(r.dataset.s))||(f==='fail'&&r.dataset.s==='fail'); });
      var hasRows=!!$('.row',d);
      d.classList.toggle('hide', hasRows ? !vis : (f!=='all'||!!s));
      if((s||f!=='all') && vis) d.open=true;
    });
  }
  function setFilter(f){ document.body.dataset.f=f; $$('.seg button').forEach(function(b){ b.setAttribute('aria-pressed', String(b.dataset.f===f)); }); apply(); }
  $$('.seg button').forEach(function(b){ b.addEventListener('click',function(){ setFilter(b.dataset.f); }); });
  $$('.stat').forEach(function(b){ b.addEventListener('click',function(){ setFilter(b.dataset.go); var t=$('#main-findings')||$('article.module'); if(t) t.scrollIntoView(); }); });
  q.addEventListener('input',apply);
  document.addEventListener('keydown',function(e){
    if(e.key==='/' && document.activeElement!==q){ e.preventDefault(); q.focus(); }
    else if(e.key==='Escape' && document.activeElement===q){ q.value=''; apply(); q.blur(); }
  });

  // свернуть / развернуть все разделы
  $('#fold').addEventListener('click',function(){ var s=$$('details.sec'), any=s.some(function(d){return !d.open}); s.forEach(function(d){ d.open=any; }); });

  // копирование сырого вывода
  $$('.copy').forEach(function(b){ b.addEventListener('click',function(){
    var t=b.nextElementSibling.textContent;
    function done(){ b.textContent='Скопировано'; setTimeout(function(){ b.textContent='Копировать'; },1500); }
    if(navigator.clipboard) navigator.clipboard.writeText(t).then(done,function(){}); });
  });

  // ---------- окно «Подробнее»: команды, запросы и ответы конкретной проверки ----------
  var ICON={copy:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
    ok:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="m5 12 5 5 9-10"/></svg>',
    more:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></svg>'};
  var STATUS={ok:'OK',info:'К сведению',warn:'Замечание',fail:'Проблема'};
  function detText(r){ if(r._dt===undefined){ var t=$('template.det',r); r._dt=t?t.content.textContent:''; } return r._dt; }
  function toast(msg){ var t=$('#toast'); if(!t){ t=document.createElement('div'); t.id='toast'; t.className='toast'; t.setAttribute('role','status'); document.body.appendChild(t); }
    t.textContent=msg; t.classList.add('on'); clearTimeout(t._h); t._h=setTimeout(function(){ t.classList.remove('on'); },1600); }
  function copy(text,btn){
    function done(){ toast('Скопировано'); if(btn){ btn.innerHTML=ICON.ok; btn.classList.add('done'); setTimeout(function(){ btn.innerHTML=ICON.copy; btn.classList.remove('done'); },1400); } }
    if(navigator.clipboard&&window.isSecureContext!==false) navigator.clipboard.writeText(text).then(done,fallback); else fallback();
    function fallback(){ var ta=document.createElement('textarea'); ta.value=text; ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select();
      try{ document.execCommand('copy'); done(); }catch(e){} document.body.removeChild(ta); }
  }

  var rowsDet=$$('.row').filter(function(r){ return $('template.det',r); });
  var dlg=document.createElement('dialog'); dlg.className='dd'; dlg.setAttribute('aria-labelledby','dd-title');
  dlg.innerHTML='<div class="dd-card"><header class="dd-head"><span class="ic dd-ic" aria-hidden="true"></span>'+
    '<div class="dd-ttl"><div class="dd-kicker"></div><h2 id="dd-title"></h2><p class="dd-msg"></p></div>'+
    '<button class="iconbtn dd-x" type="button" aria-label="Закрыть"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M6 6l12 12M18 6 6 18"/></svg></button></header>'+
    '<div class="dd-chips"></div><ul class="dd-notes"></ul><div class="dd-body" tabindex="-1" autofocus></div>'+
    '<footer class="dd-foot"><div class="dd-nav"><button type="button" class="btn dd-prev" title="Предыдущая (←)">← Назад</button><span class="dd-pos"></span><button type="button" class="btn dd-next" title="Следующая (→)">Далее →</button></div>'+
    '<div class="dd-act"><button type="button" class="btn dd-link">Ссылка</button><button type="button" class="btn dd-all">Копировать всё</button></div></footer></div>';
  document.body.appendChild(dlg);
  var cur=null;
  function chip(label,val,cls){ return val?'<span class="chip'+(cls?' '+cls:'')+'"><span class="cl">'+label+'</span>'+val+'</span>':''; }
  function esc(t){ var d=document.createElement('div'); d.textContent=t; return d.innerHTML; }
  function openDet(r){
    var t=$('template.det',r); if(!t) return;
    cur=r; var s=r.dataset.s, mod=r.closest('article'), sec=r.closest('details.sec');
    dlg.dataset.s=s; $('.dd-ic',dlg).className='ic dd-ic';
    $('.dd-kicker',dlg).textContent=[mod?mod.dataset.name:'', sec?$('h3',sec).textContent:''].filter(Boolean).join(' · ');
    $('#dd-title').textContent=t.dataset.title||r.dataset.t||'Проверка';
    var msg=$('.msg',r); $('.dd-msg',dlg).textContent=msg?msg.textContent:'';
    var code=$('.code',r), cells=$$('.num',r), meth=$('.meth',r), path=$('.path',r), ip=$('.ip',r);
    $('.dd-chips',dlg).innerHTML='<span class="chip st">'+STATUS[s]+'</span>'+
      (meth?chip('',esc(meth.textContent+' '+(path?path.textContent:'')),'mono'):(path?chip('',esc(path.textContent),'mono'):''))+
      (code?chip('HTTP',esc(code.textContent),'mono'):'')+(cells[0]&&cells[0].textContent?chip('размер',esc(cells[0].textContent)):'')+
      (cells[1]&&cells[1].textContent?chip('время',esc(cells[1].textContent)):'')+(ip&&ip.textContent?chip('IP',esc(ip.textContent),'mono'):'');
    var notes=$$('.note',r).map(function(n){ return '<li>'+esc(n.textContent)+'</li>'; }).join('');
    var ul=$('.dd-notes',dlg); ul.innerHTML=notes; ul.hidden=!notes;
    var body=$('.dd-body',dlg); body.innerHTML=''; body.appendChild(t.content.cloneNode(true)); body.scrollTop=0;
    $$('.dcopy',body).forEach(function(b){ b.innerHTML=ICON.copy; b.addEventListener('click',function(){ copy(b.previousElementSibling.textContent,b); }); });
    $$('pre.dout',body).forEach(function(p){
      if(p.scrollHeight>p.clientHeight+8){ var b=document.createElement('button'); b.type='button'; b.className='btn dmore'; b.textContent='Показать полностью';
        b.addEventListener('click',function(){ var o=p.classList.toggle('full'); b.textContent=o?'Свернуть':'Показать полностью'; }); p.after(b); }
    });
    var i=rowsDet.indexOf(r); $('.dd-pos',dlg).textContent=(i+1)+' из '+rowsDet.length;
    $('.dd-prev',dlg).disabled=i<=0; $('.dd-next',dlg).disabled=i>=rowsDet.length-1;
    if(!dlg.open){ dlg.showModal(); document.documentElement.classList.add('modal-open'); }
    body.focus({preventScroll:true});   // фокус на содержимое: стрелки и прокрутка работают сразу, без рамки на крестике
    try{ history.replaceState(null,'','#'+r.id+'~d'); }catch(e){}
    $$('.row.cur').forEach(function(x){ x.classList.remove('cur'); }); r.classList.add('cur');
  }
  function step(d){ if(!cur) return; var i=rowsDet.indexOf(cur)+d; if(i>=0&&i<rowsDet.length){ var r=rowsDet[i], sec=r.closest('details'); if(sec) sec.open=true; openDet(r); } }
  function closeDet(){ if(dlg.open) dlg.close(); }
  dlg.addEventListener('close',function(){ document.documentElement.classList.remove('modal-open');
    try{ history.replaceState(null,'',cur?'#'+cur.id:location.pathname); }catch(e){}
    if(cur){ cur.scrollIntoView({block:'nearest'}); var b=$('.more',cur); if(b) b.focus({preventScroll:true}); } });
  dlg.addEventListener('click',function(e){ if(e.target===dlg) closeDet(); });   // клик по фону
  $('.dd-x',dlg).addEventListener('click',closeDet);
  $('.dd-prev',dlg).addEventListener('click',function(){ step(-1); });
  $('.dd-next',dlg).addEventListener('click',function(){ step(1); });
  $('.dd-link',dlg).addEventListener('click',function(){ copy(location.href.split('#')[0]+'#'+cur.id+'~d'); });
  $('.dd-all',dlg).addEventListener('click',function(){
    var parts=[$('#dd-title').textContent, $('.dd-msg',dlg).textContent];
    $$('.dd-notes li',dlg).forEach(function(l){ parts.push('↳ '+l.textContent); });
    $$('.dsec',dlg).forEach(function(sx){ var h=$('h4',sx); parts.push(''); if(h) parts.push('## '+h.textContent);
      $$('dl.dkv>div, .dcmd, pre.dout',sx).forEach(function(el){
        if(el.matches('.dcmd')) parts.push('$ '+$('code',el).textContent);
        else if(el.tagName==='PRE') parts.push(el.textContent);
        else parts.push($('dt',el).textContent+': '+$('dd',el).textContent); }); });
    copy(parts.join('\n'));
  });
  dlg.addEventListener('keydown',function(e){
    if(e.key==='ArrowLeft'&&!e.target.matches('input,textarea')){ e.preventDefault(); step(-1); }
    else if(e.key==='ArrowRight'&&!e.target.matches('input,textarea')){ e.preventDefault(); step(1); }
  });

  // кнопка «Подробнее» у каждой строки с подробностями; клик по строке тоже открывает
  rowsDet.forEach(function(r){
    r.classList.add('has-det');
    var b=document.createElement('button'); b.type='button'; b.className='more'; b.setAttribute('aria-label','Подробнее: '+(r.dataset.t||($('.msg',r)||r).textContent));
    b.innerHTML='<span>Подробнее</span>'+ICON.more;
    b.addEventListener('click',function(e){ e.stopPropagation(); openDet(r); });
    var body=$('.body',r); if(body) body.after(b); else r.appendChild(b);
    r.addEventListener('click',function(e){
      if(e.target.closest('a,button')||String(window.getSelection&&window.getSelection())) return;
      openDet(r);
    });
  });
  // ссылка вида #m1-r5~d открывает подробности сразу
  (function(){ var h=location.hash.slice(1); if(/~d$/.test(h)){ var r=document.getElementById(h.slice(0,-2)); if(r){ var d=r.closest('details'); if(d) d.open=true; openDet(r); } } })();

  // переход по ссылке на строку: раскрыть её раздел
  function openHash(){ var el=location.hash&&document.getElementById(location.hash.slice(1)); if(el){ var d=el.closest('details'); if(d) d.open=true; } }
  window.addEventListener('hashchange',openHash); openHash();
  // печать: раскрыть всё
  window.addEventListener('beforeprint',function(){ $$('details.sec').forEach(function(d){ d.open=true; }); });
})();
