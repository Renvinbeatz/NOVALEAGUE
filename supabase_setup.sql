-- ============================================================
-- NØVA LEAGUE — Hardening de Segurança (parte 2)
-- Rode isso em: Supabase > SQL Editor > New query > Run
-- (depois de já ter rodado supabase_setup.sql e
--  supabase_security_upgrade.sql, nessa ordem)
-- ============================================================
-- O que este script resolve:
--
-- 1) SEQUESTRO DE CONTA: o ranking mostra publicamente o ID do
--    Free Fire de todo jogador. Como "Criar Senha" só pedia o ID
--    + uma senha nova, QUALQUER pessoa que visse o ID de alguém
--    no ranking (antes dessa pessoa criar a própria senha)
--    conseguia criar a senha primeiro e tomar a conta — kills,
--    saldo, tudo. Agora exige também um código de ativação que
--    só o ADM sabe e repassa em privado.
--
-- 2) FORÇA BRUTA: nada impedia tentar senha ou código de ativação
--    repetidamente sem limite. Agora, depois de 5 tentativas
--    erradas seguidas, a conta trava por 15 minutos.
-- ============================================================


-- ------------------------------------------------------------
-- PARTE 1 — Novas colunas
-- ------------------------------------------------------------
alter table public.jogadores
  add column if not exists activation_code text
    default upper(substr(md5(random()::text || clock_timestamp()::text), 1, 6));

alter table public.jogadores
  add column if not exists failed_login_attempts integer not null default 0;

alter table public.jogadores
  add column if not exists locked_until timestamptz;

-- Preenche o código de ativação de jogadores que já existiam antes desse script
update public.jogadores
  set activation_code = upper(substr(md5(random()::text || id::text), 1, 6))
  where activation_code is null;


-- ------------------------------------------------------------
-- PARTE 2 — Travar leitura direta dessas colunas pela chave pública
-- (o código de ativação só pode ser lido por uma sessão de admin
-- autenticada — é assim que o painel ADM consegue mostrar pra você
-- repassar no privado, sem que apareça pra mais ninguém)
-- ------------------------------------------------------------
revoke select (activation_code, failed_login_attempts, locked_until)
  on public.jogadores from anon;
grant select (activation_code) on public.jogadores to authenticated;


-- ------------------------------------------------------------
-- PARTE 3 — Trocar as funções de login/cadastro por versões com
-- exigência de código de ativação + bloqueio por tentativas
-- ------------------------------------------------------------

-- Precisa apagar a versão antiga (2 parâmetros) explicitamente:
-- só trocar o corpo com CREATE OR REPLACE não seria suficiente,
-- porque a assinatura muda (agora são 3 parâmetros) — se a função
-- antiga continuasse existindo, ela ainda poderia ser chamada
-- direto pela API, ignorando a exigência do código de ativação.
drop function if exists public.register_player_password(text, text);

create or replace function public.register_player_password(
  p_game_id text, p_activation_code text, p_password text
)
returns table (
  id bigint, nick text, "gameId" text, status text,
  kills integer, "matchesCount" integer, earnings numeric,
  has_password boolean, created_at timestamptz
)
language plpgsql
security definer
set search_path = public
as $$
declare
  v_row public.jogadores%rowtype;
begin
  if p_password is null or length(p_password) < 4 then
    raise exception 'Senha muito curta';
  end if;

  select * into v_row from public.jogadores j where j."gameId" = p_game_id;
  if not found then
    return; -- ID não existe: não revela nada além disso
  end if;

  if v_row.password is not null then
    return; -- já tem senha, não deixa sobrescrever
  end if;

  if v_row.locked_until is not null and v_row.locked_until > now() then
    raise exception 'Muitas tentativas incorretas. Tente novamente em alguns minutos.';
  end if;

  if v_row.activation_code is null or upper(v_row.activation_code) <> upper(trim(p_activation_code)) then
    update public.jogadores
      set failed_login_attempts = failed_login_attempts + 1,
          locked_until = case when failed_login_attempts + 1 >= 5
                          then now() + interval '15 minutes' else locked_until end
      where id = v_row.id;
    return; -- código errado
  end if;

  update public.jogadores
    set password = crypt(p_password, gen_salt('bf')),
        failed_login_attempts = 0,
        locked_until = null
    where id = v_row.id;

  return query
    select j.id, j.nick, j."gameId", j.status, j.kills, j."matchesCount",
           j.earnings, j.has_password, j.created_at
    from public.jogadores j
    where j.id = v_row.id;
end;
$$;

grant execute on function public.register_player_password(text, text, text) to anon, authenticated;


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
declare
  v_row public.jogadores%rowtype;
begin
  select * into v_row from public.jogadores j where j."gameId" = p_game_id;
  if not found then
    return;
  end if;

  if v_row.locked_until is not null and v_row.locked_until > now() then
    raise exception 'Conta temporariamente bloqueada por várias tentativas incorretas. Tente novamente em alguns minutos.';
  end if;

  if v_row.password is null then
    return; -- ainda não criou senha: nada pra "adivinhar" aqui
  end if;

  if v_row.password = crypt(p_password, v_row.password) then
    update public.jogadores set failed_login_attempts = 0, locked_until = null where id = v_row.id;
    return query
      select j.id, j.nick, j."gameId", j.status, j.kills, j."matchesCount",
             j.earnings, j.has_password, j.created_at
      from public.jogadores j
      where j.id = v_row.id;
    return;
  end if;

  -- senha errada: conta a tentativa
  update public.jogadores
    set failed_login_attempts = failed_login_attempts + 1,
        locked_until = case when failed_login_attempts + 1 >= 5
                        then now() + interval '15 minutes' else locked_until end
    where id = v_row.id;

  return;
end;
$$;

grant execute on function public.verify_player_password(text, text) to anon, authenticated;


-- ============================================================
-- MUDANÇA NO SEU FLUXO DE TRABALHO COMO ADM
-- ============================================================
-- Ao cadastrar um jogador novo (ID + nick), o painel ADM agora
-- mostra, embaixo do badge "PENDENTE" na tabela de jogadores, um
-- código de 6 caracteres (ex: A1B2C3). Envie esse código pro
-- jogador NO PRIVADO (WhatsApp), junto com o ID dele — é isso que
-- impede qualquer outra pessoa de criar a senha da conta dele
-- primeiro.
--
-- O código só some da tela quando o jogador finalmente cria a
-- própria senha (o badge muda pra "CRIADA").
-- ============================================================