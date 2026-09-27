export type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown'
export type Indicator = { id:number; value:string; type:string; first_seen:string; last_seen:string; verdict:Verdict; risk_score:number|null; alert_id:string|null; providers?:Provider[] }
export type Provider = { provider:string; verdict:Verdict; risk_score:number|null; metadata:Record<string, any>; checked_at?:string; status?:string }
export type Page<T> = { items:T[]; page:number; page_size:number; total:number; pages:number }
export type Activity = { id:number; action:string; message:string; details:Record<string, any>; created_at:string }
export type Health = { status:string; backend:string; database:string; providers:Record<string,{configured:boolean;status:string}> }
export type Summary = { total_indicators:number; malicious_this_week:number; unknown_indicators:number; top_types:{type:string;count:number}[]; trend:{date:string;count:number}[] }
export type EnrichmentJob = { job_id:string; alert_id:string; status:'pending'|'running'|'completed'|'failed'; total:number; completed:number; warnings:string[] }
const API_URL = (import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
export const setAdminUsername = (username:string) => sessionStorage.setItem('sentinel-admin-username',username)
export const clearAdminUsername = () => sessionStorage.removeItem('sentinel-admin-username')
export const hasAdminUsername = () => !!sessionStorage.getItem('sentinel-admin-username')
async function request<T>(path:string, init:RequestInit = {}):Promise<T> {
  let response:Response
  try { response = await fetch(`${API_URL}${path}`, { ...init, headers:{'Content-Type':'application/json','X-Admin-Username':sessionStorage.getItem('sentinel-admin-username')||'',...init.headers} }) }
  catch { throw new Error('Cannot reach Sentinel API. Check that the backend is running.') }
  const body = await response.json().catch(()=>({detail:'Unexpected API response'}))
  if (!response.ok) throw new Error(typeof body.detail === 'string' ? body.detail : `Request failed (${response.status})`)
  return body as T
}
export const api = {
  session:()=>request<{authenticated:boolean}>('/api/session'),
  health:()=>request<Health>('/api/health'),
  extract:(text:string)=>request<{alert_id:string;created_at:string;count:number;indicators:Indicator[]}>('/api/extract',{method:'POST',body:JSON.stringify({text})}),
  enrich:(alert_id:string,indicators:number[])=>request<EnrichmentJob>('/api/enrich',{method:'POST',body:JSON.stringify({alert_id,indicators})}),
  job:(jobId:string)=>request<EnrichmentJob>(`/api/jobs/${encodeURIComponent(jobId)}`),
  indicators:(params:Record<string,string|number>)=>request<Page<Indicator>>(`/api/indicators?${new URLSearchParams(Object.entries(params).map(([k,v])=>[k,String(v)]))}`),
  detail:(id:number)=>request<Indicator & {source_alert:{id:string;raw_text:string;created_at:string}|null;related:Indicator[]}>(`/api/indicators/${id}`),
  activity:(page=1)=>request<Page<Activity>>(`/api/activity?page=${page}&page_size=30`),
  summary:()=>request<Summary>('/api/summary')
}
