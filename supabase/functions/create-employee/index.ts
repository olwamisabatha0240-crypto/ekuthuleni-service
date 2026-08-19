import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'

Deno.serve(async (req) => {
  if (req.method !== 'POST') return new Response('Method not allowed', { status: 405 })

  const supabaseUrl = Deno.env.get('SUPABASE_URL')!
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!
  const serviceRoleKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const authHeader = req.headers.get('Authorization')
  if (!authHeader) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } })

  const userClient = createClient(supabaseUrl, anonKey, { global: { headers: { Authorization: authHeader } } })
  const { data: { user } } = await userClient.auth.getUser()
  if (!user) return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers: { 'Content-Type': 'application/json' } })

  const adminClient = createClient(supabaseUrl, serviceRoleKey)
  const { data: adminProfile } = await adminClient.from('employee_profiles').select('role,active').eq('id', user.id).single()
  if (!adminProfile || adminProfile.role !== 'admin' || !adminProfile.active) return new Response(JSON.stringify({ error: 'Admin access required' }), { status: 403, headers: { 'Content-Type': 'application/json' } })

  const body = await req.json()
  const full_name = String(body.full_name || '').trim()
  const email = String(body.email || '').trim().toLowerCase()
  const password = String(body.password || '')
  const phone = String(body.phone || '').trim() || null
  const role = String(body.role || 'employee')

  if (!full_name || !email || !password) return new Response(JSON.stringify({ error: 'Full name, email and password are required' }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  if (!['employee','manager'].includes(role)) return new Response(JSON.stringify({ error: 'Only employee or manager accounts can be created here' }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  if (password.length < 8) return new Response(JSON.stringify({ error: 'Password must be at least 8 characters' }), { status: 400, headers: { 'Content-Type': 'application/json' } })

  const { data: created, error: createError } = await adminClient.auth.admin.createUser({ email, password, email_confirm: true })
  if (createError || !created.user) return new Response(JSON.stringify({ error: createError?.message || 'Could not create authentication account' }), { status: 400, headers: { 'Content-Type': 'application/json' } })

  const { error: profileError } = await adminClient.from('employee_profiles').insert({ id: created.user.id, full_name, role, phone, active: true })
  if (profileError) {
    await adminClient.auth.admin.deleteUser(created.user.id)
    return new Response(JSON.stringify({ error: profileError.message }), { status: 400, headers: { 'Content-Type': 'application/json' } })
  }

  return new Response(JSON.stringify({ success: true, employee: { id: created.user.id, full_name, email, role, phone, active: true } }), { status: 201, headers: { 'Content-Type': 'application/json' } })
})
