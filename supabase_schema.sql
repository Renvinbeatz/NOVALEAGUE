-- =========================================================
-- NØVA LEAGUE — Schema completo do Supabase
-- Rode este arquivo inteiro em: Supabase > SQL Editor > New query > Run
-- =========================================================

create extension if not exists pgcrypto;

-- =========================================================
-- TABELAS
-- =========================================================

create table if not exists jogadores (
  id uuid primary key default gen_random_uuid(),
  nick text not null,
  "gameId" text not null unique,
  password_hash text,
  activation_code text,
  status text not null default 'normal',
  kills int not null default 0,
  "matchesCount" int not null default 0,
  earnings numeric not null default 0,
  failed_attempts int not null default 0,
  locked_until timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists partidas (
  id uuid primary key default gen_random_uuid(),
  number text not null,
  "playerId" uuid references jogadores(id) on delete set null,
  "playerGameId" text not null,
  "playerNick" text not null,
  date text,
  kills int not null default 0,
  pos int not null default 1,
  total numeric not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists cupons (
  id uuid primary key default gen_random_uuid(),
  code text not null,
  discount text not null,
  valid text,
  created_at timestamptz not null default now()
);

create table if not exists mensagens (
  id uuid primary key default gen_random_uuid(),
  "recipientId" text not null, -- 'all' ou o id (uuid, como texto) do jogador
  text text not null,
  date text,
  "readBy" jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

-- Quem pode logar como ADM. Precisa existir primeiro em Authentication > Users
-- (crie o usuário lá, pegue o UUID dele, e insira aqui — veja instruções no fim do arquivo)
create table if not exists admin_users (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null default 'admin',
  created_at timestamptz not null default now()
);

-- =========================================================
-- FUNÇÃO AUXILIAR: verifica se o usuário logado é admin
-- =========================================================

create or replace function is_admin()
returns boolean
language sql
security definer
stable
as $$
  select exists (
    select 1 from admin_users where user_id = auth.uid()
  );
$$;

-- =========================================================
-- VIEW PÚBLICA DE JOGADORES
-- (esconde password_hash e activation_code de quem não é admin)
-- =========================================================

create or replace view public_jogadores as
select
  id,
  nick,
  "gameId",
  status,
  kills,
  "matchesCount",
  earnings,
  (password_hash is not null) as has_password
from jogadores;

grant select on public_jogadores to anon, authenticated;

-- =========================================================
-- ROW LEVEL SECURITY
-- =========================================================

alter table jogadores enable row level security;
alter table partidas enable row level security;
alter table cupons enable row level security;
alter table mensagens enable row level security;
alter table admin_users enable row level security;

-- jogadores: NINGUÉM lê/escreve direto na tabela, exceto admin.
-- Leitura pública passa pela view public_jogadores (sem senha/código).
drop policy if exists "admin full access jogadores" on jogadores;
create policy "admin full access jogadores" on jogadores
  for all using (is_admin()) with check (is_admin());

-- partidas: leitura pública, escrita só admin
drop policy if exists "public read partidas" on partidas;
create policy "public read partidas" on partidas for select using (true);
drop policy if exists "admin write partidas" on partidas;
create policy "admin write partidas" on partidas
  for all using (is_admin()) with check (is_admin());

-- cupons: leitura pública, escrita só admin
drop policy if exists "public read cupons" on cupons;
create policy "public read cupons" on cupons for select using (true);
drop policy if exists "admin write cupons" on cupons;
create policy "admin write cupons" on cupons
  for all using (is_admin()) with check (is_admin());

-- mensagens: leitura pública (o front filtra o que é "seu"), escrita só admin
drop policy if exists "public read mensagens" on mensagens;
create policy "public read mensagens" on mensagens for select using (true);
drop policy if exists "admin write mensagens" on mensagens;
create policy "admin write mensagens" on mensagens
  for all using (is_admin()) with check (is_admin());

-- admin_users: só admin lê (evita vazar quem é admin)
drop policy if exists "admin read admin_users" on admin_users;
create policy "admin read admin_users" on admin_users for select using (is_admin());

-- =========================================================
-- FUNÇÕES DE LOGIN DO JOGADOR (rodam com privilégio elevado,
-- então conseguem comparar o hash sem expor a coluna pro cliente)
-- =========================================================

-- Login: confere ID + senha, com bloqueio de 15min após 5 erros
create or replace function player_login(p_game_id text, p_password text)
returns table(id uuid, nick text, "gameId" text, status text, kills int, "matchesCount" int, earnings numeric, error text)
language plpgsql
security definer
as $$
declare
  v jogadores%rowtype;
begin
  select * into v from jogadores where jogadores."gameId" = p_game_id;

  if not found then
    return query select null::uuid, null::text, null::text, null::text, null::int, null::int, null::numeric, 'ID não encontrado no servidor!'::text;
    return;
  end if;

  if v.password_hash is null then
    return query select null::uuid, null::text, null::text, null::text, null::int, null::int, null::numeric, 'Este ID ainda não possui senha! Use o código de ativação.'::text;
    return;
  end if;

  if v.locked_until is not null and v.locked_until > now() then
    return query select null::uuid, null::text, null::text, null::text, null::int, null::int, null::numeric,
      ('Conta bloqueada temporariamente. Tente novamente após ' || to_char(v.locked_until, 'HH24:MI') || '.')::text;
    return;
  end if;

  if v.password_hash = crypt(p_password, v.password_hash) then
    update jogadores set failed_attempts = 0, locked_until = null where jogadores.id = v.id;
    return query select v.id, v.nick, v."gameId", v.status, v.kills, v."matchesCount", v.earnings, null::text;
  else
    update jogadores
    set failed_attempts = v.failed_attempts + 1,
        locked_until = case when v.failed_attempts + 1 >= 5 then now() + interval '15 minutes' else v.locked_until end
    where jogadores.id = v.id;
    return query select null::uuid, null::text, null::text, null::text, null::int, null::int, null::numeric, 'Senha incorreta!'::text;
  end if;
end;
$$;

-- Registro: qualquer um que souber o ID pode criar a senha (sem código de
-- ativação). Fica mais simples de usar, mas quem souber o ID de outra
-- pessoa (o ID é público no ranking) consegue criar senha pra conta dela
-- antes do dono — se isso virar problema, reative o fluxo com activation_code.
drop function if exists player_register(text, text, text);
create or replace function player_register(p_game_id text, p_new_password text)
returns table(id uuid, nick text, "gameId" text, error text)
language plpgsql
security definer
as $$
declare
  v jogadores%rowtype;
begin
  select * into v from jogadores where jogadores."gameId" = p_game_id;

  if not found then
    return query select null::uuid, null::text, null::text, 'ID inválido! Você precisa estar cadastrado pelo ADM.'::text;
    return;
  end if;

  if v.password_hash is not null then
    return query select null::uuid, null::text, null::text, 'Este ID já possui senha cadastrada! Use a aba Entrar.'::text;
    return;
  end if;

  update jogadores
  set password_hash = crypt(p_new_password, gen_salt('bf'))
  where jogadores.id = v.id;

  return query select v.id, v.nick, v."gameId", null::text;
end;
$$;

-- Gera um código de ativação de 6 caracteres pro admin repassar no privado
create or replace function generate_activation_code()
returns text
language sql
as $$
  select upper(substr(md5(random()::text), 1, 6));
$$;

-- Marca uma mensagem como lida pelo jogador (evita que o jogador escreva
-- direto na tabela de mensagens)
create or replace function mark_message_read(p_message_id uuid, p_player_id uuid)
returns void
language plpgsql
security definer
as $$
begin
  update mensagens
  set "readBy" = "readBy" || to_jsonb(p_player_id::text)
  where id = p_message_id
    and not ("readBy" @> to_jsonb(p_player_id::text));
end;
$$;

grant execute on function player_login(text, text) to anon, authenticated;
grant execute on function player_register(text, text) to anon, authenticated;
grant execute on function mark_message_read(uuid, uuid) to anon, authenticated;

-- =========================================================
-- FUNÇÕES DE ESCRITA EM LOTE (usadas pelo painel ADM)
-- Cada uma faz N jogadores em UMA chamada só, em vez do front
-- disparar uma requisição por jogador.
-- =========================================================

-- Nova partida criada pelo modal "+ NOVA PARTIDA" (um ou mais jogadores,
-- cada um podendo ter valor/kill e bônus diferentes)
create or replace function add_match_with_players(
  p_match_number text,
  p_match_date text,
  p_entries jsonb -- [{"playerId": "uuid", "kills": 5, "pos": 1, "killValue": 4.0, "bonus": 10.0}, ...]
)
returns int
language plpgsql
security definer
as $$
declare
  v_entry jsonb;
  v_total numeric;
  v_count int := 0;
begin
  if not is_admin() then
    raise exception 'Não autorizado';
  end if;

  for v_entry in select * from jsonb_array_elements(p_entries)
  loop
    v_total := ((v_entry->>'kills')::int * (v_entry->>'killValue')::numeric) + (v_entry->>'bonus')::numeric;

    insert into partidas (number, "playerId", "playerGameId", "playerNick", date, kills, pos, total)
    select p_match_number, j.id, j."gameId", j.nick, p_match_date,
           (v_entry->>'kills')::int, (v_entry->>'pos')::int, v_total
    from jogadores j where j.id = (v_entry->>'playerId')::uuid;

    update jogadores
    set kills = kills + (v_entry->>'kills')::int,
        "matchesCount" = "matchesCount" + 1,
        earnings = earnings + v_total
    where id = (v_entry->>'playerId')::uuid;

    v_count := v_count + 1;
  end loop;

  return v_count;
end;
$$;

-- Importação em massa de resultados (colar lista ID, Kills, Posição).
-- Um único valor de kill/top1/top2 vale pra lista inteira.
create or replace function bulk_import_matches(
  p_match_number text,
  p_match_date text,
  p_kill_value numeric,
  p_top1_value numeric,
  p_top2_value numeric,
  p_entries jsonb -- [{"gameId": "12345678", "kills": 5, "pos": 1}, ...]
)
returns table(imported_count int, not_found jsonb)
language plpgsql
security definer
as $$
declare
  v_entry jsonb;
  v_player jogadores%rowtype;
  v_bonus numeric;
  v_total numeric;
  v_imported int := 0;
  v_not_found jsonb := '[]'::jsonb;
begin
  if not is_admin() then
    raise exception 'Não autorizado';
  end if;

  for v_entry in select * from jsonb_array_elements(p_entries)
  loop
    select * into v_player from jogadores where "gameId" = (v_entry->>'gameId');

    if not found then
      v_not_found := v_not_found || jsonb_build_array(v_entry->>'gameId');
      continue;
    end if;

    v_bonus := 0;
    if (v_entry->>'pos')::int = 1 then v_bonus := p_top1_value;
    elsif (v_entry->>'pos')::int = 2 then v_bonus := p_top2_value;
    end if;

    v_total := ((v_entry->>'kills')::int * p_kill_value) + v_bonus;

    insert into partidas (number, "playerId", "playerGameId", "playerNick", date, kills, pos, total)
    values (p_match_number, v_player.id, v_player."gameId", v_player.nick, p_match_date,
            (v_entry->>'kills')::int, (v_entry->>'pos')::int, v_total);

    update jogadores
    set kills = kills + (v_entry->>'kills')::int,
        "matchesCount" = "matchesCount" + 1,
        earnings = earnings + v_total
    where id = v_player.id;

    v_imported := v_imported + 1;
  end loop;

  return query select v_imported, v_not_found;
end;
$$;

-- Exclui uma partida inteira (todos os jogadores dela) e reverte os
-- pontos/prêmios de cada um, em uma única chamada.
create or replace function delete_match_group(p_number text, p_date text)
returns int
language plpgsql
security definer
as $$
declare
  v_row partidas%rowtype;
  v_count int := 0;
begin
  if not is_admin() then
    raise exception 'Não autorizado';
  end if;

  for v_row in
    select * from partidas
    where number = p_number and coalesce(date, 'sem_data') = coalesce(p_date, 'sem_data')
  loop
    update jogadores
    set kills = greatest(0, kills - v_row.kills),
        "matchesCount" = greatest(0, "matchesCount" - 1),
        earnings = greatest(0, round((earnings - v_row.total)::numeric, 2))
    where id = v_row."playerId";

    delete from partidas where id = v_row.id;
    v_count := v_count + 1;
  end loop;

  return v_count;
end;
$$;

grant execute on function add_match_with_players(text, text, jsonb) to authenticated;
grant execute on function bulk_import_matches(text, text, numeric, numeric, numeric, jsonb) to authenticated;
grant execute on function delete_match_group(text, text) to authenticated;

-- =========================================================
-- COMO TERMINAR A CONFIGURAÇÃO (leia com calma):
--
-- 1) Vá em Authentication > Users no painel do Supabase e clique em
--    "Add user" para cada admin (você, e quem mais for administrar).
--    Defina um e-mail e senha de verdade — NÃO fica mais no código.
--
-- 2) Copie o UUID de cada usuário criado (aparece na lista) e rode,
--    pra cada um, trocando o UUID:
--
--    insert into admin_users (user_id) values ('COLE-O-UUID-AQUI');
--
-- 3) Vá em Project Settings > API e copie a "Project URL" e a chave
--    "anon public" — são elas que vão no SUPABASE_URL e
--    SUPABASE_ANON_KEY do index.html.
-- =========================================================