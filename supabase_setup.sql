-- ============================================================
-- NØVA LEAGUE — Hardening de Segurança
-- Rode isso em: Supabase > SQL Editor > New query > Run
-- (depois de já ter rodado o supabase_setup.sql anterior)
-- ============================================================
-- O que este script resolve:
--
-- 1) As senhas de ADM estavam escritas em texto puro dentro do
--    HTML público do site (qualquer um via "Ver código-fonte" via
--    o painel). Agora o login de ADM passa a usar o Supabase Auth
--    de verdade — nenhuma senha fica no código.
--
-- 2) As tabelas estavam com política "allow all": qualquer pessoa
--    com a chave pública (que fica exposta no HTML, isso é normal
--    e esperado) conseguia ler e editar QUALQUER linha de QUALQUER
--    tabela direto pela API do Supabase, inclusive por fora do site
--    — sem precisar logar como ADM. Isso incluía ler a senha de
--    todos os jogadores, alterar kills/ganhos, apagar jogadores,
--    apagar partidas, criar cupons falsos, etc.
--
-- 3) A senha dos jogadores era gravada e lida em texto puro. Agora
--    é armazenada com hash (bcrypt) e a verificação acontece dentro
--    do banco via função seguraSQL — a senha em texto nunca mais
--    trafega de volta pro navegador em nenhuma consulta.
-- ============================================================


-- ------------------------------------------------------------
-- PARTE 1 — Extensão para hash de senha
-- ------------------------------------------------------------
create extension if not exists pgcrypto;


-- ------------------------------------------------------------
-- PARTE 2 — Tabela de administradores
-- Vincula contas do Supabase Auth (auth.users) a quem pode
-- administrar o site. Ver instruções no final deste arquivo
-- pra criar as contas e inserir aqui.
-- ------------------------------------------------------------
create table if not exists public.admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;

-- Um admin pode ver a lista de admins (só isso — sem insert/update/delete pelo site).
create policy "admins podem ver admin_users" on public.admin_users
  for select
  to authenticated
  using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));


-- ------------------------------------------------------------
-- PARTE 3 — Migrar a senha dos jogadores para hash
-- ------------------------------------------------------------

-- Coluna calculada: indica só se a senha existe, sem expor o valor.
alter table public.jogadores
  add column if not exists has_password boolean generated always as (password is not null) stored;

-- Converte as senhas que já estavam em texto puro para hash (idempotente:
-- se já rodar de novo em cima de um hash, não tem problema, mas evite rodar 2x
-- sem necessidade). Se a tabela estiver vazia ou zerada, não faz nada.
update public.jogadores
  set password = crypt(password, gen_salt('bf'))
  where password is not null
    and password not like '$2%';  -- pula quem já estiver em formato bcrypt


-- ------------------------------------------------------------
-- PARTE 4 — Funções seguras (RPC) para login/cadastro de senha
-- e para marcar mensagem como lida. Rodam com privilégio elevado
-- (SECURITY DEFINER) só para essa ação específica e nada mais —
-- isso permite manter a tabela travada para o público em geral.
-- ------------------------------------------------------------

-- Cadastra a senha (hash) de um jogador já existente, só se ele
-- ainda não tiver senha. Devolve os dados públicos do jogador.
create or replace function public.register_player_password(p_game_id text, p_password text)
returns table (
  id bigint, nick text, "gameId" text, status text,
  kills integer, "matchesCount" integer, earnings numeric,
  has_password boolean, created_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
begin
  if p_password is null or length(p_password) < 4 then
    raise exception 'Senha muito curta';
  end if;

  update public.jogadores j
    set password = crypt(p_password, gen_salt('bf'))
    where j."gameId" = p_game_id
      and j.password is null;

  if not found then
    return;
  end if;

  return query
    select j.id, j.nick, j."gameId", j.status, j.kills, j."matchesCount",
           j.earnings, j.has_password, j.created_at
    from public.jogadores j
    where j."gameId" = p_game_id;
end;
$$;

-- Verifica ID + senha e devolve os dados públicos do jogador se bater.
-- Não retorna nada (0 linhas) se a senha estiver errada ou não existir.
create or replace function public.verify_player_password(p_game_id text, p_password text)
returns table (
  id bigint, nick text, "gameId" text, status text,
  kills integer, "matchesCount" integer, earnings numeric,
  has_password boolean, created_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
begin
  return query
    select j.id, j.nick, j."gameId", j.status, j.kills, j."matchesCount",
           j.earnings, j.has_password, j.created_at
    from public.jogadores j
    where j."gameId" = p_game_id
      and j.password is not null
      and j.password = crypt(p_password, j.password);
end;
$$;

-- Marca uma mensagem como lida só pelo próprio jogador (não permite
-- editar texto, destinatário nem nada além do array de leitura).
create or replace function public.mark_message_read(p_message_id bigint, p_player_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.mensagens m
    set "readBy" = (
      select coalesce(jsonb_agg(distinct v), '[]'::jsonb)
      from (
        select jsonb_array_elements(coalesce(m."readBy", '[]'::jsonb)) as v
        union
        select to_jsonb(p_player_id)
      ) x
    )
    where m.id = p_message_id
      and (m."recipientId" = 'all' or m."recipientId" = p_player_id::text);
end;
$$;

-- Essas funções rodam com privilégio elevado, mas fazem só a ação descrita.
-- Precisam ser chamáveis por qualquer visitante (jogador não está logado
-- no Supabase Auth, só no app).
grant execute on function public.register_player_password(text, text) to anon, authenticated;
grant execute on function public.verify_player_password(text, text) to anon, authenticated;
grant execute on function public.mark_message_read(bigint, bigint) to anon, authenticated;


-- ------------------------------------------------------------
-- PARTE 5 — Travar a coluna "password" para leitura direta
-- Mesmo com a tabela liberada para SELECT, ninguém consegue mais
-- ler a coluna "password" (nem em hash) — só as funções acima,
-- que rodam com privilégio próprio, conseguem tocar nela.
-- ------------------------------------------------------------
revoke select (password) on public.jogadores from anon, authenticated;


-- ------------------------------------------------------------
-- PARTE 6 — RLS: substitui as políticas "libera tudo" por regras reais
-- Leitura pública continua liberada (ranking, partidas, cupons e
-- mensagens são conteúdo do campeonato, isso é intencional).
-- Escrita (inserir/editar/apagar) passa a exigir uma sessão
-- autenticada que esteja na tabela admin_users.
-- ------------------------------------------------------------

drop policy if exists "allow all - jogadores" on public.jogadores;
drop policy if exists "allow all - partidas" on public.partidas;
drop policy if exists "allow all - cupons" on public.cupons;
drop policy if exists "allow all - mensagens" on public.mensagens;

create policy "leitura publica - jogadores" on public.jogadores
  for select to anon, authenticated using (true);
create policy "admins escrevem - jogadores" on public.jogadores
  for insert to authenticated with check (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));
create policy "admins atualizam - jogadores" on public.jogadores
  for update to authenticated
  using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()))
  with check (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));
create policy "admins apagam - jogadores" on public.jogadores
  for delete to authenticated using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));

create policy "leitura publica - partidas" on public.partidas
  for select to anon, authenticated using (true);
create policy "admins gerenciam - partidas" on public.partidas
  for all to authenticated
  using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()))
  with check (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));

create policy "leitura publica - cupons" on public.cupons
  for select to anon, authenticated using (true);
create policy "admins gerenciam - cupons" on public.cupons
  for all to authenticated
  using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()))
  with check (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));

create policy "leitura publica - mensagens" on public.mensagens
  for select to anon, authenticated using (true);
create policy "admins gerenciam - mensagens" on public.mensagens
  for all to authenticated
  using (exists (select 1 from public.admin_users a where a.user_id = auth.uid()))
  with check (exists (select 1 from public.admin_users a where a.user_id = auth.uid()));
-- (marcar como lida continua funcionando pra qualquer jogador através
-- da função mark_message_read acima, que não depende dessas políticas)


-- ============================================================
-- PRÓXIMOS PASSOS MANUAIS (fazer no painel do Supabase, não aqui)
-- ============================================================
-- 1. Vá em Authentication > Users > Add User e crie uma conta para
--    cada administrador (e-mail + senha NOVA — as senhas antigas
--    que estavam no código já vazaram publicamente, não reaproveite
--    nenhuma delas). Marque "Auto Confirm User" ao criar, já que
--    esses e-mails provavelmente não recebem o link de confirmação.
--
-- 2. Depois de criar cada conta, copie o UUID dela (aparece na lista
--    de usuários) e rode, para cada admin:
--
--    insert into public.admin_users (user_id) values ('COLE-O-UUID-AQUI');
--
-- 3. Pronto — só quem estiver logado com uma dessas contas consegue
--    usar o painel ADM. Delete os 3 usuários antigos de auth.users,
--    se sobrarem, e troque a senha de qualquer admin cuja senha
--    antiga (a que estava no HTML) tenha sido reaproveitada em
--    outro lugar.
-- ============================================================