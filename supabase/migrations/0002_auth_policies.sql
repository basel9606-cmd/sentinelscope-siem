-- SentinelScope SIEM: least-privilege access policies for Supabase Auth.

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name, role)
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data ->> 'display_name', split_part(coalesce(new.email, 'Analyst'), '@', 1)),
    'viewer'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute procedure public.handle_new_user();

create or replace function public.is_soc_analyst()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles
    where role in ('admin', 'analyst')
      and (
        id = auth.uid()
        or lower(email) = lower(coalesce(auth.jwt() ->> 'email', ''))
      )
  );
$$;

create or replace function public.current_soc_profile()
returns table(display_name text, role text)
language sql
stable
security definer
set search_path = public
as $$
  select p.display_name, p.role
  from public.profiles p
  where p.id = auth.uid()
     or lower(p.email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  order by (p.id = auth.uid()) desc
  limit 1;
$$;

grant execute on function public.current_soc_profile() to authenticated;

create policy "profiles: own record" on public.profiles
for select to authenticated using (
  id = auth.uid()
  or lower(email) = lower(coalesce(auth.jwt() ->> 'email', ''))
);

create policy "profiles: own update" on public.profiles
for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

create policy "cases: authenticated read" on public.cases
for select to authenticated using (true);

create policy "cases: analysts create" on public.cases
for insert to authenticated with check (public.is_soc_analyst());

create policy "cases: analysts update" on public.cases
for update to authenticated using (public.is_soc_analyst()) with check (public.is_soc_analyst());

create policy "alerts: authenticated read" on public.alerts
for select to authenticated using (true);

create policy "alerts: analysts write" on public.alerts
for all to authenticated using (public.is_soc_analyst()) with check (public.is_soc_analyst());

create policy "case alerts: authenticated read" on public.case_alerts
for select to authenticated using (true);

create policy "case alerts: analysts write" on public.case_alerts
for all to authenticated using (public.is_soc_analyst()) with check (public.is_soc_analyst());

create policy "case notes: authenticated read" on public.case_notes
for select to authenticated using (true);

create policy "case notes: analysts create" on public.case_notes
for insert to authenticated with check (public.is_soc_analyst() and author_id = auth.uid());

create policy "audit: authenticated read" on public.audit_log
for select to authenticated using (true);

create policy "audit: analysts write" on public.audit_log
for insert to authenticated with check (public.is_soc_analyst() and actor_id = auth.uid());
