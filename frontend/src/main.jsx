import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import {LineChart,Line,XAxis,YAxis,Tooltip,ResponsiveContainer} from 'recharts';
import './style.css';
const API='http://localhost:8000';
function Login({onLogin}){const [username,setUsername]=useState('admin'),[password,setPassword]=useState('gridshield'),[error,setError]=useState('');const submit=async e=>{e.preventDefault();setError('');try{let r=await fetch(API+'/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});let x=await r.json();if(!r.ok)throw new Error(x.detail||'Login failed');localStorage.setItem('gridshield_token',x.access_token);onLogin(x.access_token)}catch(e){setError(e.message)}};return <div className="login"><form onSubmit={submit}><div className="logo">GRIDSHIELD</div><p>Operator Security Console</p><input value={username} onChange={e=>setUsername(e.target.value)} placeholder="Username"/><input value={password} onChange={e=>setPassword(e.target.value)} type="password" placeholder="Password"/><button className="primary">Authenticate Operator</button>{error&&<div className="error">{error}</div>}<small>Demo credentials: admin / gridshield</small></form></div>}
function App(){const [token,setToken]=useState(localStorage.getItem('gridshield_token'));const [devices,setDevices]=useState([]),[alerts,setAlerts]=useState([]),[energy,setEnergy]=useState({total_power:0,points:[]}),[forecast,setForecast]=useState({current:0,forecast:[]}),[health,setHealth]=useState({mqtt:false});const headers={'Authorization':'Bearer '+token};const load=async()=>{try{let [d,a,e,f,h]=await Promise.all(['/api/devices','/api/alerts','/api/energy','/api/forecast','/api/health'].map(x=>fetch(API+x,{headers}).then(async r=>{if(r.status===401){localStorage.removeItem('gridshield_token');setToken(null);throw new Error('auth')}return r.json()})));setDevices(d);setAlerts(a);setEnergy(e);setForecast(f);setHealth(h)}catch{}};useEffect(()=>{if(!token)return;load();let t=setInterval(load,1000);return()=>clearInterval(t)},[token]);if(!token)return <Login onLogin={setToken}/>;
const act = async (path, id) => {
    try {
        const response = await fetch(API + path, {
            method: 'POST',
            headers: {
                ...headers,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                device_id: id
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || 'Attack request failed');
        }

        console.log(
            `[GridShield] ${data.attack || 'action'} started for ${id}`
        );

        await load();

    } catch (error) {
        console.error('[GridShield] Attack failed:', error);
        alert(`Attack failed: ${error.message}`);
    }
};
const logout=()=>{localStorage.removeItem('gridshield_token');setToken(null)};const chart=energy.points.map(x=>({name:x.device,power:x.power}));const auth=devices.filter(x=>x.authenticated).length;const threats=devices.filter(x=>x.threat>=30).length;return <div className="app"><header><div><h1>GRIDSHIELD</h1><p>Secure IoT Cloud Architecture for Smart Grid</p></div><div className="headerRight"><b className={health.mqtt?'secure':'risk'}>● MQTT {health.mqtt?'CONNECTED':'DISCONNECTED'}</b><button onClick={logout}>Logout</button></div></header><section className="cards"><Card t="DEVICES" v={devices.length}/><Card t="AUTHENTICATED" v={auth}/><Card t="THREATS" v={threats}/><Card t="TOTAL LOAD" v={(energy.total_power/1000).toFixed(2)+' kW'}/></section><div className="grid"><section className="panel"><h2>Device Status & Response</h2>{devices.map(d=><div className="device" key={d.id}><span className={d.status==='quarantined'||d.status==='blocked'?'dot red':'dot'}></span><b>{d.id}</b><span className="caps">{d.status}</span><span>{d.power.toFixed(0)} W</span><span className={d.threat>=70?'risk':''}>Risk {d.threat}</span><div>   <button
    className="attack energy"
    onClick={() => act('/api/simulate/anomaly', d.id)}
>
    ⚡ Energy Attack
</button>

<button
    className="attack traffic"
    onClick={() => act('/api/simulate/flood', d.id)}
>
    🚨 Traffic Attack
</button>

<button
    className="recover"
    onClick={() => act('/api/recover', d.id)}
>
    🔓 Recover
</button>  </div></div>)}</section><section className="panel"><h2>Live Energy</h2><ResponsiveContainer width="100%" height={300}><LineChart data={chart}><XAxis dataKey="name"/><YAxis/><Tooltip/><Line type="monotone" dataKey="power" strokeWidth={3}/></LineChart></ResponsiveContainer></section></div><div className="grid"><section className="panel"><h2>Load Forecast</h2><div className="forecast"><b>Current</b><strong>{forecast.current} W</strong>{forecast.forecast?.map((v,i)=><span key={i}>+{i+1}h: {v} W</span>)}</div><p className="muted">Prototype trend forecast for demonstration.</p></section><section className="panel"><h2>Security Alerts</h2><div className="alerts">{alerts.slice(0,8).map((a,i)=><div className="alert" key={i}><b>{a.type}</b> · {a.device_id} · score {a.score}<small>{a.detail}</small></div>)}</div></section></div><div className="foot">GridShield v2.1 · Independent MQTT identity per meter · Device-key authentication · JWT operator access</div></div>}
function Card({t,v}){return <div className="card"><span>{t}</span><strong>{v}</strong></div>};createRoot(document.getElementById('root')).render(<App/>);
