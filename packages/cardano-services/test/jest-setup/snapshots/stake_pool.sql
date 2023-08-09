--
-- PostgreSQL database dump
--

-- Dumped from database version 11.5
-- Dumped by pg_dump version 11.5

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: stake_pool; Type: DATABASE; Schema: -; Owner: postgres
--

CREATE DATABASE stake_pool WITH TEMPLATE = template0 ENCODING = 'UTF8' LC_COLLATE = 'en_US.utf8' LC_CTYPE = 'en_US.utf8';


ALTER DATABASE stake_pool OWNER TO postgres;

\connect stake_pool

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgboss; Type: SCHEMA; Schema: -; Owner: postgres
--

CREATE SCHEMA pgboss;


ALTER SCHEMA pgboss OWNER TO postgres;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: 
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: job_state; Type: TYPE; Schema: pgboss; Owner: postgres
--

CREATE TYPE pgboss.job_state AS ENUM (
    'created',
    'retry',
    'active',
    'completed',
    'expired',
    'cancelled',
    'failed'
);


ALTER TYPE pgboss.job_state OWNER TO postgres;

--
-- Name: stake_pool_status_enum; Type: TYPE; Schema: public; Owner: postgres
--

CREATE TYPE public.stake_pool_status_enum AS ENUM (
    'activating',
    'active',
    'retired',
    'retiring'
);


ALTER TYPE public.stake_pool_status_enum OWNER TO postgres;

SET default_tablespace = '';

SET default_with_oids = false;

--
-- Name: archive; Type: TABLE; Schema: pgboss; Owner: postgres
--

CREATE TABLE pgboss.archive (
    id uuid NOT NULL,
    name text NOT NULL,
    priority integer NOT NULL,
    data jsonb,
    state pgboss.job_state NOT NULL,
    retrylimit integer NOT NULL,
    retrycount integer NOT NULL,
    retrydelay integer NOT NULL,
    retrybackoff boolean NOT NULL,
    startafter timestamp with time zone NOT NULL,
    startedon timestamp with time zone,
    singletonkey text,
    singletonon timestamp without time zone,
    expirein interval NOT NULL,
    createdon timestamp with time zone NOT NULL,
    completedon timestamp with time zone,
    keepuntil timestamp with time zone NOT NULL,
    on_complete boolean NOT NULL,
    output jsonb,
    archivedon timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE pgboss.archive OWNER TO postgres;

--
-- Name: job; Type: TABLE; Schema: pgboss; Owner: postgres
--

CREATE TABLE pgboss.job (
    id uuid DEFAULT public.gen_random_uuid() NOT NULL,
    name text NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    data jsonb,
    state pgboss.job_state DEFAULT 'created'::pgboss.job_state NOT NULL,
    retrylimit integer DEFAULT 0 NOT NULL,
    retrycount integer DEFAULT 0 NOT NULL,
    retrydelay integer DEFAULT 0 NOT NULL,
    retrybackoff boolean DEFAULT false NOT NULL,
    startafter timestamp with time zone DEFAULT now() NOT NULL,
    startedon timestamp with time zone,
    singletonkey text,
    singletonon timestamp without time zone,
    expirein interval DEFAULT '00:15:00'::interval NOT NULL,
    createdon timestamp with time zone DEFAULT now() NOT NULL,
    completedon timestamp with time zone,
    keepuntil timestamp with time zone DEFAULT (now() + '14 days'::interval) NOT NULL,
    on_complete boolean DEFAULT false NOT NULL,
    output jsonb,
    block_slot integer
);


ALTER TABLE pgboss.job OWNER TO postgres;

--
-- Name: schedule; Type: TABLE; Schema: pgboss; Owner: postgres
--

CREATE TABLE pgboss.schedule (
    name text NOT NULL,
    cron text NOT NULL,
    timezone text,
    data jsonb,
    options jsonb,
    created_on timestamp with time zone DEFAULT now() NOT NULL,
    updated_on timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE pgboss.schedule OWNER TO postgres;

--
-- Name: subscription; Type: TABLE; Schema: pgboss; Owner: postgres
--

CREATE TABLE pgboss.subscription (
    event text NOT NULL,
    name text NOT NULL,
    created_on timestamp with time zone DEFAULT now() NOT NULL,
    updated_on timestamp with time zone DEFAULT now() NOT NULL
);


ALTER TABLE pgboss.subscription OWNER TO postgres;

--
-- Name: version; Type: TABLE; Schema: pgboss; Owner: postgres
--

CREATE TABLE pgboss.version (
    version integer NOT NULL,
    maintained_on timestamp with time zone,
    cron_on timestamp with time zone
);


ALTER TABLE pgboss.version OWNER TO postgres;

--
-- Name: block; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.block (
    height integer NOT NULL,
    hash character(64) NOT NULL,
    slot integer NOT NULL
);


ALTER TABLE public.block OWNER TO postgres;

--
-- Name: block_data; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.block_data (
    block_height integer NOT NULL,
    data bytea NOT NULL
);


ALTER TABLE public.block_data OWNER TO postgres;

--
-- Name: current_pool_metrics; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.current_pool_metrics (
    stake_pool_id character(56) NOT NULL,
    slot integer NOT NULL,
    minted_blocks integer NOT NULL,
    live_delegators integer NOT NULL,
    active_stake bigint NOT NULL,
    live_stake bigint NOT NULL,
    live_pledge bigint NOT NULL,
    live_saturation numeric NOT NULL,
    active_size numeric NOT NULL,
    live_size numeric NOT NULL,
    apy numeric NOT NULL
);


ALTER TABLE public.current_pool_metrics OWNER TO postgres;

--
-- Name: pool_metadata; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.pool_metadata (
    id integer NOT NULL,
    ticker character varying NOT NULL,
    name character varying NOT NULL,
    description character varying NOT NULL,
    homepage character varying NOT NULL,
    hash character varying NOT NULL,
    ext jsonb,
    stake_pool_id character(56),
    pool_update_id bigint NOT NULL
);


ALTER TABLE public.pool_metadata OWNER TO postgres;

--
-- Name: pool_metadata_id_seq; Type: SEQUENCE; Schema: public; Owner: postgres
--

CREATE SEQUENCE public.pool_metadata_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.pool_metadata_id_seq OWNER TO postgres;

--
-- Name: pool_metadata_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: postgres
--

ALTER SEQUENCE public.pool_metadata_id_seq OWNED BY public.pool_metadata.id;


--
-- Name: pool_registration; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.pool_registration (
    id bigint NOT NULL,
    reward_account character varying NOT NULL,
    pledge numeric(20,0) NOT NULL,
    cost numeric(20,0) NOT NULL,
    margin jsonb NOT NULL,
    margin_percent real NOT NULL,
    relays jsonb NOT NULL,
    owners jsonb NOT NULL,
    vrf character(64) NOT NULL,
    metadata_url character varying,
    metadata_hash character(64),
    stake_pool_id character(56) NOT NULL,
    block_slot integer NOT NULL
);


ALTER TABLE public.pool_registration OWNER TO postgres;

--
-- Name: pool_retirement; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.pool_retirement (
    id bigint NOT NULL,
    retire_at_epoch integer NOT NULL,
    stake_pool_id character(56) NOT NULL,
    block_slot integer NOT NULL
);


ALTER TABLE public.pool_retirement OWNER TO postgres;

--
-- Name: stake_pool; Type: TABLE; Schema: public; Owner: postgres
--

CREATE TABLE public.stake_pool (
    id character(56) NOT NULL,
    status public.stake_pool_status_enum NOT NULL,
    last_registration_id bigint,
    last_retirement_id bigint
);


ALTER TABLE public.stake_pool OWNER TO postgres;

--
-- Name: pool_metadata id; Type: DEFAULT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_metadata ALTER COLUMN id SET DEFAULT nextval('public.pool_metadata_id_seq'::regclass);


--
-- Data for Name: archive; Type: TABLE DATA; Schema: pgboss; Owner: postgres
--

COPY pgboss.archive (id, name, priority, data, state, retrylimit, retrycount, retrydelay, retrybackoff, startafter, startedon, singletonkey, singletonon, expirein, createdon, completedon, keepuntil, on_complete, output, archivedon) FROM stdin;
\.


--
-- Data for Name: job; Type: TABLE DATA; Schema: pgboss; Owner: postgres
--

COPY pgboss.job (id, name, priority, data, state, retrylimit, retrycount, retrydelay, retrybackoff, startafter, startedon, singletonkey, singletonon, expirein, createdon, completedon, keepuntil, on_complete, output, block_slot) FROM stdin;
70e0cf0f-037d-43ca-8d0c-598864d3cd5a	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:43:56.468059+00	2023-08-16 11:44:56.461558+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:41:56.468059+00	2023-08-16 11:44:56.474351+00	2023-08-16 11:51:56.468059+00	f	\N	\N
2e2ed687-a56d-4301-9edf-c404d142d363	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:32:26.615595+00	2023-08-16 11:32:26.618984+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:32:26.615595+00	2023-08-16 11:32:26.629133+00	2023-08-16 11:40:26.615595+00	f	\N	\N
a89bb0be-c9c2-4761-8cbe-60ca87e50871	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:45:01.729163+00	2023-08-16 11:45:04.735708+00	\N	2023-08-16 11:45:00	00:15:00	2023-08-16 11:44:04.729163+00	2023-08-16 11:45:04.807809+00	2023-08-16 11:46:01.729163+00	f	\N	\N
3e58d656-0bf6-45be-b1b4-098313a520d7	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:46:01.805808+00	2023-08-16 11:46:04.764032+00	\N	2023-08-16 11:46:00	00:15:00	2023-08-16 11:45:04.805808+00	2023-08-16 11:46:04.770182+00	2023-08-16 11:47:01.805808+00	f	\N	\N
950a2100-eac8-4b3c-9b69-3da367c34592	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:47:01.768107+00	2023-08-16 11:47:04.789278+00	\N	2023-08-16 11:47:00	00:15:00	2023-08-16 11:46:04.768107+00	2023-08-16 11:47:04.796481+00	2023-08-16 11:48:01.768107+00	f	\N	\N
76e820f3-edfe-4afb-9fbf-04d13a03b569	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:46:56.476257+00	2023-08-16 11:47:56.465725+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:44:56.476257+00	2023-08-16 11:47:56.484449+00	2023-08-16 11:54:56.476257+00	f	\N	\N
f98ac6ba-8d42-4a41-a0bb-0c162ce6de52	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:32:26.623643+00	2023-08-16 11:32:56.455966+00	\N	2023-08-16 11:32:00	00:15:00	2023-08-16 11:32:26.623643+00	2023-08-16 11:32:56.459435+00	2023-08-16 11:33:26.623643+00	f	\N	\N
f133c3b1-cca5-474e-a3eb-65f9a291c20f	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:32:56.44639+00	2023-08-16 11:32:56.45137+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:32:56.44639+00	2023-08-16 11:32:56.461217+00	2023-08-16 11:40:56.44639+00	f	\N	\N
4df251f7-3ce0-4241-bc48-f7e7e26252b7	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:50:01.837314+00	2023-08-16 11:50:04.857463+00	\N	2023-08-16 11:50:00	00:15:00	2023-08-16 11:49:04.837314+00	2023-08-16 11:50:04.870306+00	2023-08-16 11:51:01.837314+00	f	\N	\N
d8d0413f-68df-4e89-8a47-d9ddef963fdf	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:49:56.486827+00	2023-08-16 11:50:56.468337+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:47:56.486827+00	2023-08-16 11:50:56.474613+00	2023-08-16 11:57:56.486827+00	f	\N	\N
926415ec-342d-40ea-b0a2-52d1076ee061	pool-metadata	0	{"poolId": "pool1h5hgjazd5mjpyl26708ag7en4we38cjzuv27w9c7nxgvvl2emyc", "metadataJson": {"url": "http://file-server/SP3.json", "hash": "6d3ce01216ac833311cbb44c6793325bc14f12d559a83b2237f60eeb66e85f25"}, "poolRegistrationId": "2810000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:26.844601+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:26.844601+00	2023-08-16 11:32:56.504964+00	2023-08-30 11:32:26.844601+00	f	\N	281
7300e632-bbb5-4f39-a29b-df25ab71037e	pool-metadata	0	{"poolId": "pool1fljeydsfvwejj60ns72j853ygf3vtxae9ry8ppuzgdxkw9x3mm5", "metadataJson": {"url": "http://file-server/SP1.json", "hash": "14ea470ac1deb37c5d5f2674cfee849d40fa0fe5265fccc78f2fdb4cec73dfc7"}, "poolRegistrationId": "820000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:26.727934+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:26.727934+00	2023-08-16 11:32:56.509195+00	2023-08-30 11:32:26.727934+00	f	\N	82
3e6471bf-12f5-4524-87ed-b489ac27e733	pool-metadata	0	{"poolId": "pool1svasg66clvn2rf0phz2yrtcphk4cgpecjseqmck562w22xa578g", "metadataJson": {"url": "http://file-server/SP5.json", "hash": "0f118a34e20bd77f8a9ba5e27481eba54d063630c4c1c017bad11a2fba615501"}, "poolRegistrationId": "4620000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:26.953214+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:26.953214+00	2023-08-16 11:32:56.518373+00	2023-08-30 11:32:26.953214+00	f	\N	462
213af3a6-ecba-4f40-96ce-cf4680abdace	pool-metadata	0	{"poolId": "pool1d9pmphwkkezcdha48qzjg6fr784xaq9yad2llj0hwcrp7ldnufq", "metadataJson": {"url": "http://file-server/SP4.json", "hash": "09dd809e0fecfc0ef01e3bc225d54a60b4de3eed39a8574a9e350d2ec952dc8d"}, "poolRegistrationId": "3960000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:26.899274+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:26.899274+00	2023-08-16 11:32:56.520173+00	2023-08-30 11:32:26.899274+00	f	\N	396
07ddceb4-b532-4b89-995e-f4f3f4f9074b	pool-metadata	0	{"poolId": "pool1tzrwtvn8ssr3ap90suzuk9rplv47v7hxusmfndrrrhsvc3u03gl", "metadataJson": {"url": "http://file-server/SP6.json", "hash": "3806b0c100c6019d0ed25233ad823a1c505fd6bd05aad617be09d420082914ba"}, "poolRegistrationId": "5790000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:27.00917+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:27.00917+00	2023-08-16 11:32:56.520746+00	2023-08-30 11:32:27.00917+00	f	\N	579
9264601b-ac63-41d9-a5e3-61667b6202d9	pool-metadata	0	{"poolId": "pool1xyd8d2jr3qac25f4lzzmq4aunyzqct08p275s7f3zvplyx5mz3t", "metadataJson": {"url": "http://file-server/SP7.json", "hash": "c431584ed48f8ce7dda609659a4905e90bf7ca95e4f8b4fddb7e05ce4315d405"}, "poolRegistrationId": "6750000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:27.07064+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:27.07064+00	2023-08-16 11:32:56.521517+00	2023-08-30 11:32:27.07064+00	f	\N	675
e89b7700-3304-4181-ab8b-20fab20cc41d	pool-metadata	0	{"poolId": "pool13fpyflv8uw83sxg4sdpj36g7fm3qds2z93rnlcatna887f4lhdm", "metadataJson": {"url": "http://file-server/SP11.json", "hash": "4c1c15c4b9fd85a94b5d89e1031db403dd65da928289c40fa2513165b77dcdc9"}, "poolRegistrationId": "11170000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:27.344864+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:27.344864+00	2023-08-16 11:32:56.522694+00	2023-08-30 11:32:27.344864+00	f	\N	1117
8a8c533d-7478-496f-83ba-eebb64686a3b	pool-metadata	0	{"poolId": "pool19qxvm4eu4m2ucaqcx2w6p08d7sy2ljta895qnve2m53hcc4nsgy", "metadataJson": {"url": "http://file-server/SP10.json", "hash": "c054facebb7063a319711b4d680a4c513005663a1d47e8e8a41a4cef45812ffd"}, "poolRegistrationId": "9890000000000"}	completed	1000000	0	21600	f	2023-08-16 11:32:27.246927+00	2023-08-16 11:32:56.464723+00	\N	\N	00:15:00	2023-08-16 11:32:27.246927+00	2023-08-16 11:32:56.522047+00	2023-08-30 11:32:27.246927+00	f	\N	989
0ca9d850-dd4a-465d-9b78-ac8c2ce9b44b	pool-metrics	0	{"slot": 3096}	completed	0	0	0	f	2023-08-16 11:32:28.304024+00	2023-08-16 11:32:56.464923+00	\N	\N	00:15:00	2023-08-16 11:32:28.304024+00	2023-08-16 11:32:56.744997+00	2023-08-30 11:32:28.304024+00	f	\N	3096
d0f0a763-4759-432e-88c1-fa42d8755255	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:33:01.460219+00	2023-08-16 11:33:04.458474+00	\N	2023-08-16 11:33:00	00:15:00	2023-08-16 11:32:56.460219+00	2023-08-16 11:33:04.48259+00	2023-08-16 11:34:01.460219+00	f	\N	\N
70e1add2-a2ae-4dfa-8dd4-6fed67f27b64	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:34:01.477314+00	2023-08-16 11:34:04.48409+00	\N	2023-08-16 11:34:00	00:15:00	2023-08-16 11:33:04.477314+00	2023-08-16 11:34:04.490914+00	2023-08-16 11:35:01.477314+00	f	\N	\N
5c241ee1-e441-4933-89df-cdfaff389511	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:35:01.489058+00	2023-08-16 11:35:04.506115+00	\N	2023-08-16 11:35:00	00:15:00	2023-08-16 11:34:04.489058+00	2023-08-16 11:35:04.512775+00	2023-08-16 11:36:01.489058+00	f	\N	\N
bc07055f-f03a-4bb8-8d21-bcc9bfd711fe	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:34:56.465905+00	2023-08-16 11:35:56.453714+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:32:56.465905+00	2023-08-16 11:35:56.466448+00	2023-08-16 11:42:56.465905+00	f	\N	\N
16bb569b-44a4-4095-b561-9033d270f75f	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:36:01.51117+00	2023-08-16 11:36:04.536137+00	\N	2023-08-16 11:36:00	00:15:00	2023-08-16 11:35:04.51117+00	2023-08-16 11:36:04.54898+00	2023-08-16 11:37:01.51117+00	f	\N	\N
e9610fb1-0073-4c56-aed7-28a17df352e1	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:37:01.54736+00	2023-08-16 11:37:04.559485+00	\N	2023-08-16 11:37:00	00:15:00	2023-08-16 11:36:04.54736+00	2023-08-16 11:37:04.566667+00	2023-08-16 11:38:01.54736+00	f	\N	\N
7c48730b-4e74-45d5-b919-3e83a10a3855	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:38:01.564964+00	2023-08-16 11:38:04.581615+00	\N	2023-08-16 11:38:00	00:15:00	2023-08-16 11:37:04.564964+00	2023-08-16 11:38:04.594819+00	2023-08-16 11:39:01.564964+00	f	\N	\N
978176c4-a55d-4a1e-8b34-b908183b434d	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:37:56.46827+00	2023-08-16 11:38:56.45575+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:35:56.46827+00	2023-08-16 11:38:56.462535+00	2023-08-16 11:45:56.46827+00	f	\N	\N
3fa81ad7-82d1-4c10-ad51-5780904f0601	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:39:01.593111+00	2023-08-16 11:39:04.602985+00	\N	2023-08-16 11:39:00	00:15:00	2023-08-16 11:38:04.593111+00	2023-08-16 11:39:04.608738+00	2023-08-16 11:40:01.593111+00	f	\N	\N
89d61127-1ad7-40e2-939c-45cdca415056	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:40:01.607189+00	2023-08-16 11:40:04.624927+00	\N	2023-08-16 11:40:00	00:15:00	2023-08-16 11:39:04.607189+00	2023-08-16 11:40:04.639941+00	2023-08-16 11:41:01.607189+00	f	\N	\N
4b9aa5ab-92f9-4501-95af-bb38c7945ce6	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:41:01.638366+00	2023-08-16 11:41:04.647747+00	\N	2023-08-16 11:41:00	00:15:00	2023-08-16 11:40:04.638366+00	2023-08-16 11:41:04.653575+00	2023-08-16 11:42:01.638366+00	f	\N	\N
59897663-c2dd-418b-bee6-63352e2b0d88	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:40:56.465092+00	2023-08-16 11:41:56.459237+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:38:56.465092+00	2023-08-16 11:41:56.465711+00	2023-08-16 11:48:56.465092+00	f	\N	\N
8685368f-d025-4a19-b7b9-30b68fcf815e	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:42:01.651985+00	2023-08-16 11:42:04.671825+00	\N	2023-08-16 11:42:00	00:15:00	2023-08-16 11:41:04.651985+00	2023-08-16 11:42:04.678754+00	2023-08-16 11:43:01.651985+00	f	\N	\N
6747ddd6-ea86-4aea-9fde-d7ec8ee559ac	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:43:01.677125+00	2023-08-16 11:43:04.693455+00	\N	2023-08-16 11:43:00	00:15:00	2023-08-16 11:42:04.677125+00	2023-08-16 11:43:04.706943+00	2023-08-16 11:44:01.677125+00	f	\N	\N
665717a9-9df9-4784-8cf4-8edcc98cf202	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:44:01.705402+00	2023-08-16 11:44:04.71719+00	\N	2023-08-16 11:44:00	00:15:00	2023-08-16 11:43:04.705402+00	2023-08-16 11:44:04.730869+00	2023-08-16 11:45:01.705402+00	f	\N	\N
ec1e329e-0464-4cc7-8740-0af3ec399e7b	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:48:01.794443+00	2023-08-16 11:48:04.810368+00	\N	2023-08-16 11:48:00	00:15:00	2023-08-16 11:47:04.794443+00	2023-08-16 11:48:04.824291+00	2023-08-16 11:49:01.794443+00	f	\N	\N
9955bb49-76a9-441d-9f89-63358b1757a6	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:51:01.868779+00	2023-08-16 11:51:04.881976+00	\N	2023-08-16 11:51:00	00:15:00	2023-08-16 11:50:04.868779+00	2023-08-16 11:51:04.890713+00	2023-08-16 11:52:01.868779+00	f	\N	\N
ba7f12b2-fa8d-4909-92b6-6adc75143bac	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:49:01.822494+00	2023-08-16 11:49:04.832881+00	\N	2023-08-16 11:49:00	00:15:00	2023-08-16 11:48:04.822494+00	2023-08-16 11:49:04.839385+00	2023-08-16 11:50:01.822494+00	f	\N	\N
61e95830-be56-4cee-a023-c60986e5ea1e	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:52:01.888718+00	2023-08-16 11:52:04.905163+00	\N	2023-08-16 11:52:00	00:15:00	2023-08-16 11:51:04.888718+00	2023-08-16 11:52:04.9186+00	2023-08-16 11:53:01.888718+00	f	\N	\N
b335e707-af3c-452c-8de1-fdab34fb6152	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:53:01.913405+00	2023-08-16 11:53:04.925845+00	\N	2023-08-16 11:53:00	00:15:00	2023-08-16 11:52:04.913405+00	2023-08-16 11:53:04.932673+00	2023-08-16 11:54:01.913405+00	f	\N	\N
960590b3-8d2b-4282-98df-053d7f2a749b	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:52:56.476672+00	2023-08-16 11:53:56.47125+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:50:56.476672+00	2023-08-16 11:53:56.476033+00	2023-08-16 12:00:56.476672+00	f	\N	\N
2dd1aae6-2043-48ff-b8db-269763909c86	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:54:01.93086+00	2023-08-16 11:54:04.953301+00	\N	2023-08-16 11:54:00	00:15:00	2023-08-16 11:53:04.93086+00	2023-08-16 11:54:04.966835+00	2023-08-16 11:55:01.93086+00	f	\N	\N
59813643-df00-4f27-a5b0-5749687e673f	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:55:01.965213+00	2023-08-16 11:55:04.974231+00	\N	2023-08-16 11:55:00	00:15:00	2023-08-16 11:54:04.965213+00	2023-08-16 11:55:05.000192+00	2023-08-16 11:56:01.965213+00	f	\N	\N
f3dca09b-4e13-47c4-8ecf-f6811308d0cc	pool-metrics	0	{"slot": 10066}	completed	0	0	0	f	2023-08-16 11:55:40.211123+00	2023-08-16 11:55:41.146822+00	\N	\N	00:15:00	2023-08-16 11:55:40.211123+00	2023-08-16 11:55:41.341959+00	2023-08-30 11:55:40.211123+00	f	\N	10066
f41e7298-1be4-4a30-99f2-7d6becdfe71b	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:56:01.998346+00	2023-08-16 11:56:05.001314+00	\N	2023-08-16 11:56:00	00:15:00	2023-08-16 11:55:04.998346+00	2023-08-16 11:56:05.01428+00	2023-08-16 11:57:01.998346+00	f	\N	\N
ebf4eae7-be6a-4d54-ae2d-63164f595e0b	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:55:56.478083+00	2023-08-16 11:56:56.473899+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:53:56.478083+00	2023-08-16 11:56:56.478801+00	2023-08-16 12:03:56.478083+00	f	\N	\N
e9982b92-db6a-4bff-97b1-ee06b458ff01	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:57:01.012712+00	2023-08-16 11:57:01.025088+00	\N	2023-08-16 11:57:00	00:15:00	2023-08-16 11:56:05.012712+00	2023-08-16 11:57:01.03845+00	2023-08-16 11:58:01.012712+00	f	\N	\N
8344aa8d-2690-4067-bcf1-2f05bdcaaad9	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:58:01.036874+00	2023-08-16 11:58:01.047183+00	\N	2023-08-16 11:58:00	00:15:00	2023-08-16 11:57:01.036874+00	2023-08-16 11:58:01.052575+00	2023-08-16 11:59:01.036874+00	f	\N	\N
bf242ba3-d20f-4d53-85f9-6c423abf0a79	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 11:59:01.051049+00	2023-08-16 11:59:01.072996+00	\N	2023-08-16 11:59:00	00:15:00	2023-08-16 11:58:01.051049+00	2023-08-16 11:59:01.07996+00	2023-08-16 12:00:01.051049+00	f	\N	\N
c57e758d-f18a-4eae-8fe2-7680dbc866d9	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 11:58:56.480521+00	2023-08-16 11:59:56.478409+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:56:56.480521+00	2023-08-16 11:59:56.483589+00	2023-08-16 12:06:56.480521+00	f	\N	\N
556c5753-8ea7-42c2-871a-63d019ee66f4	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 12:00:01.077702+00	2023-08-16 12:00:01.097155+00	\N	2023-08-16 12:00:00	00:15:00	2023-08-16 11:59:01.077702+00	2023-08-16 12:00:01.103876+00	2023-08-16 12:01:01.077702+00	f	\N	\N
e8022aa1-dfd2-42a1-b19a-62fc6bdc24b4	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 12:01:01.102325+00	2023-08-16 12:01:01.12128+00	\N	2023-08-16 12:01:00	00:15:00	2023-08-16 12:00:01.102325+00	2023-08-16 12:01:01.127312+00	2023-08-16 12:02:01.102325+00	f	\N	\N
04fb5c84-12a1-4d9d-8fba-2ec1d712c368	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 12:02:01.125643+00	2023-08-16 12:02:01.145737+00	\N	2023-08-16 12:02:00	00:15:00	2023-08-16 12:01:01.125643+00	2023-08-16 12:02:01.152904+00	2023-08-16 12:03:01.125643+00	f	\N	\N
7c86d576-328a-407e-8aaf-d41009cc2194	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 12:01:56.485346+00	2023-08-16 12:02:56.480334+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 11:59:56.485346+00	2023-08-16 12:02:56.492596+00	2023-08-16 12:09:56.485346+00	f	\N	\N
ae0b9111-b257-4b67-bab7-559491cd138f	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 12:03:01.151001+00	2023-08-16 12:03:01.167937+00	\N	2023-08-16 12:03:00	00:15:00	2023-08-16 12:02:01.151001+00	2023-08-16 12:03:01.18158+00	2023-08-16 12:04:01.151001+00	f	\N	\N
f93c0cd9-eb8b-47cd-bb5c-fb5970b55413	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 12:04:01.179954+00	2023-08-16 12:04:01.192284+00	\N	2023-08-16 12:04:00	00:15:00	2023-08-16 12:03:01.179954+00	2023-08-16 12:04:01.206683+00	2023-08-16 12:05:01.179954+00	f	\N	\N
f1707546-45e1-4f3d-9611-4d10be2fb1c0	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 12:05:01.204964+00	2023-08-16 12:05:01.220109+00	\N	2023-08-16 12:05:00	00:15:00	2023-08-16 12:04:01.204964+00	2023-08-16 12:05:01.225636+00	2023-08-16 12:06:01.204964+00	f	\N	\N
af9db51a-f010-45a2-be14-9e674cfcc1b4	__pgboss__maintenance	0	\N	completed	0	0	0	f	2023-08-16 12:04:56.494451+00	2023-08-16 12:05:56.484034+00	__pgboss__maintenance	\N	00:15:00	2023-08-16 12:02:56.494451+00	2023-08-16 12:05:56.49773+00	2023-08-16 12:12:56.494451+00	f	\N	\N
e45d38f5-6124-47f6-9091-74af3ad2489b	__pgboss__maintenance	0	\N	created	0	0	0	f	2023-08-16 12:07:56.499385+00	\N	__pgboss__maintenance	\N	00:15:00	2023-08-16 12:05:56.499385+00	\N	2023-08-16 12:15:56.499385+00	f	\N	\N
1166b151-ef1f-4b58-a94d-e6b20dec244d	__pgboss__cron	0	\N	created	2	0	0	f	2023-08-16 12:07:01.248158+00	\N	\N	2023-08-16 12:07:00	00:15:00	2023-08-16 12:06:01.248158+00	\N	2023-08-16 12:08:01.248158+00	f	\N	\N
b57387b8-21ab-4b77-a39d-da76ec857ab5	__pgboss__cron	0	\N	completed	2	0	0	f	2023-08-16 12:06:01.224101+00	2023-08-16 12:06:01.242722+00	\N	2023-08-16 12:06:00	00:15:00	2023-08-16 12:05:01.224101+00	2023-08-16 12:06:01.249666+00	2023-08-16 12:07:01.224101+00	f	\N	\N
\.


--
-- Data for Name: schedule; Type: TABLE DATA; Schema: pgboss; Owner: postgres
--

COPY pgboss.schedule (name, cron, timezone, data, options, created_on, updated_on) FROM stdin;
\.


--
-- Data for Name: subscription; Type: TABLE DATA; Schema: pgboss; Owner: postgres
--

COPY pgboss.subscription (event, name, created_on, updated_on) FROM stdin;
\.


--
-- Data for Name: version; Type: TABLE DATA; Schema: pgboss; Owner: postgres
--

COPY pgboss.version (version, maintained_on, cron_on) FROM stdin;
20	2023-08-16 12:05:56.496425+00	2023-08-16 12:06:01.246324+00
\.


--
-- Data for Name: block; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.block (height, hash, slot) FROM stdin;
0	19fb5b7298b0cab0aaf86fbfcacb00545329b338fffea29181ff21042194a77e	2
1	74330bae5c2820c8bb49228ac52f3395f29da5738439f7476011b706f22f1f72	3
2	d48915a02439c27928fa0d2c1f2aaf4731fa7981333a0dda6184600d25cf635e	14
3	11ca38bc4f38c6d40d9a85a0974e6d08f344c08bd3ceead83b1fba6e7d43a160	17
4	f190a318c13a584a0a33fca754641a31e87c2c51960da02860300d8c890156ef	34
5	a1465caf359b2f4639c2fbe56edca9fbf9fbd03ca04e057a9b24ea4b0fd3778b	35
6	c4992a8bf2df919eb973aab0be1806024a9b15481cc615a671abf831b2cac3bd	36
7	150aa21cd01489842c52396a5458defbc33ec0f1b3e965cca5e0be1e763f9192	38
8	f352fcfbaa0402e0ff154d3c97a3b5d0ae38bcad95acb37f9d1001c341c9cd14	62
9	49815a213f670ea5039c5d23f3cec03900da9b94cb61cb81405d56861cf03344	71
10	ea15fa9dbd309ca75d024aeadfb81cd8c8bb8c23f1754a01a588935f5a14d56d	82
11	fff601fb498b3819f9871a636e6067bb874df5af7949895702cbc02af9b6b0d3	87
12	137bcfd3717a05766a01d296aad469979a7194d0a39c747ba7bf9fa2d2df9d81	105
13	44344a0a2a6adb4917eed152d96c6f012f658d56f7ebfd414a52f05ee68a4948	109
14	15df472bb0ba5e3db7bf422865948e1068eb9608a0aacaa7be78900372e73992	112
15	bb8cb15cebe151b01150427962af7cc161aec99ae44a37d8b96bcf758030fe3f	114
16	717d0db425f57e411c40db8404c44dbdffb5f03d21b1137ed0555ff28be87b5a	119
17	c5cb794ec50a58d8d0ff59bbe119201ae9a3f207406cb00aa1d46a6458d35a4b	158
18	cdc6b9b15c482b1f1be440aa02c8fc3bd9f19f3b516c9bfbcc4f636e77fdae67	169
19	999284eea364d6d40e4a27071a18776619a0a8df85c0a65dc7eea2cc4fc68844	171
20	6de0ab6cdc54f7a47ff7f2f4f7ff1ae5bce1c016f74772cd6ec4e089a98adf70	181
21	2bfa54c4b7e22d26f01103f7ccc9827d0512681280dcd5a95dc15e9ab533c093	183
22	aa21ef2f1402528c84043457404797e807eeac0431353adf9f42746a0f3fadcf	193
23	04b855d480e200804e05af0c9cc9d3d8ae3a4e5828b0b6c880070fb1c03a557e	238
24	0c7b24fcedef19b38eedfe2c9fb3ba68c18f9f7d32094f8c14621c00988b75a3	245
25	1db7be0ad798fd95b143ec3123d47a21aa2e7cf671328134e2acf57ace68fc6c	257
26	528f8dc004cbd632543d9c43fc04bc6ccf638912cacc41cf1e93c8e20119cfe7	259
27	824d16de11a7f7f175c129e10873a7a2e4a774af6c8a2b7c214856b3f4a66a0e	269
28	f2c2f6dd3bcae5f5a8d2af593299d371957876717955a0157f22c7048b8294cd	274
29	5d6f97b9f7dbb7f73f4096b5469d8c208e12c4ae48a4a15dba3258c27ebfede5	281
30	c554952fba59775eb9eb478a2b47587d19b3bb20df2f11c06a7e8d8f44961cde	292
31	4831795288597ac80288aeb5c8894350699aa37badd77b080d960765360d0dd1	294
32	f54aaeccc4e9763298853c9a0b56b6cbe0c54b77075ad81981321e8d0a44e515	339
33	63aaaddccc8f5c3aa2a0c0670b6ba8d94369f7c762c22bd57e6252e437d4a7c5	356
34	32ed7894217fca2b43abdaf8c54842443963b5753557bb054206212a6a3f122c	361
35	6d5c791b408bea824321dc1dc29a325d25de960b78b5cfa65d1b83c74e3bb357	381
36	127478b3bce345f232b2b6150e20ddd98d4298fb0977c7384ef36f5298694dab	385
37	8aa4cea589dee31571cad336084a8f008c3419f590c11549e4062bb7fd67a1da	396
38	5e14048dfa71a2721cde8934b12f5bd304e74a29efd84596d19086c0ad1ebc7a	404
39	a0f4d98b591fd194219491d9053929e6c3a5a7d3bb9d86055d9a9ef61dd5a5f6	415
40	bbba7333b78ae66f41728f150cb5420ae04cecc9cfef7bf68ba08cb374b51f5b	421
41	7261a696a78c6c48234fad0b6b97ee5471b3f5e89a1c0f84939d3343706984a8	426
42	174788a4fb53c561830dea98339ad454e098d38b186d8946930309ed820e51c7	433
43	8ae089ce320a8629636c3d2039803a51c28d542d71f0c263508b4ee4d945aba0	441
44	1c4c26dce1a220a2c6727d73f9d0358aaf3bd08e409d0af010f56ac4e0700021	453
45	c39c01fdca96957dace14b37991e94da9639346701608e2e4d382ed73a1d88d3	459
46	bf542a096c2369d9959b5d4c61039f97e3b1c255534fc31c695687fbddee2661	462
47	f5f7e16e909f6409d97d9f205b8dada8706720c8a29dc2e8e799783d171ca059	467
48	75c23744d3c33b2b6c8cc21e1101a0a4d8aa28901b940d847908e388ae74890f	498
49	ae59972e4287cf0577935e6749c6bf4b979fe7e39b9a0d894052aa2baf722a28	499
50	c8e4d75cad1d9301b913f7be1674a7261b3870070cae1c410b32ec045fd81df0	508
51	db7d2a4f840c1460659ee2b985eba906c4317066da5fc7dcb03b48cfde4f6afa	512
52	59fb9ebf22b4d629bf6dfa7999d934cab0b63a573533f6b4d6253098fcc0a304	551
53	3a78d757dade19d399eac7a0208862905e1dc8bd385e7dc9b1eb3e87cf8be06a	552
54	56152d64c9851e972e5266314da0858da0e7babb487a8d020b8a3175922ec810	558
55	95d9fe16e52a5211808aefe54f884663e3f1aaa1bc51d62b016d228ea42b2589	562
56	676dfde0b9580b2ce30c2c7175c0ab8c9601c678f2c275329f4fb41f209b7439	579
57	3e9c753f4b5f5f39d639f22aea28a3a6b0d2013b47d2236b1b8959513ecd1172	582
58	c590919f7fd850c94d8e5d0da3cc3c3ca9443381f5c12fc1f4b837f4845658d5	591
59	91b0ae45892d4f93d2d0bf20626444a03101d94214d6f80f44dde8e654160e4f	592
60	fa68d3b0ca4ca7b987ac33792edc049274d87fb802b7b99ed6dc63882708182e	613
61	8e282af8a290c4628fe10b9f94ea8b24110730fee760a28b57f9c06f95dfc037	615
62	9749858837736121686186897e2b90a5f24eefd42e208d8b1ed2a8dc22704406	635
63	771288ce59f93f77c77d8b5d8af65099555b06689421faa94fbeb7e9ddca1003	658
64	1fcd331e7b99dc2e43c1d73262d1134fe8305121706f790c847dae65425a70f3	663
65	f646dd246bebb0214f9607198b8df1a06b33e5e32d350273d1c0f3cd8afddf15	675
66	df47989a3e152ca108aec836a07fea1da3e4d16efa103bb1e6f978cfab9b2502	691
67	cd9fad3cda5616110f3311459b08c0bcb92f1a37edaed123c32172a93244cda2	734
68	f7a32fc6d1fdaa72feece8967519a75402271c1d543c7921715f11f2483333b6	736
69	facdbf55e0e5fc2d23a153508a1484a30843d50541e2e9d6cf4ca1b2e047e0a9	753
70	63e7aa464fdede0af9494d79108a6d5eefb158f807527f2ca2e8a7407f022fc9	754
71	ffa27dbfc95bfebd7b6ca6f26616cb72081a12e20209369784bdc6e4497f3176	760
72	82210124c9949c5c8d6a8685bc0e7826ab2a0ac3336cc518684bc38b415f4317	778
73	8f913fce66d16c0274969bbfdeb62f2dbec5d3d20535acb30d8a8b76fed930a5	789
74	f508f3f4b252596ca4914ddcd2140e6c093b47b013ed2fd26bc5c1f6a8f89bce	800
75	973df67dcc7fd770bc3e470b01a4415f01863e2ee5639d2fcf97845a9887130a	804
76	4ed6dc9078c9da5589fba5269f449bfa61f5dd954cc2bb5fc8513f7f80757900	816
77	ba3fc900ede5acb659663341acdc947895eece3c742b2d47ba66ee10125dfae5	828
78	06be26768e82eab75d17d1ca52ba95c0d38c026a1c99b829027a64772c5b4567	833
79	3e1761ae687aa0f0ac6f2929f21f1ab6bdcfd9bf588a05cefe034c2b136cf420	836
80	68e90e09a2b923740ca04ee8d9f75d691a7461b115eef4b7f228ce8e01edd948	842
81	05b8abc7572128d6605c1cb27539cbe34947c869ecdb14c722b023376ee16245	845
82	38c1ab7263a3793762701c03e85a59b1063734af18b5b08b9262d5636d2853de	853
83	796b85a8b09fe4576de823b30850c429b6de05dfefc98a261235aa2b81be3958	866
84	c1f0e53d617bd2a6c41caf4063613d1849ffc3a709fcb1ada1d53dcd66e6e5ff	882
85	03b641b9dd43dde43dfcf8661cb4981afd0fb83a50f5fe9163e2af2bf1285835	896
86	b40960261340416c394a8b06c06afb06701a7f64a8bc3b456c6d37372ecad444	910
87	421d11950eef6f105d9a263065519eb7f678b5cee8a5448162ba2e6e082800f0	928
88	6fba9b85c94d7f9ef1ef4d88cec743fa86dd06d414d8b0dfb9f6bc38b51d02f5	944
89	2555abdeacd6e18fba561e69bc80dda6c1ba56278a92824f911c797bf691c345	954
90	e3d27720263485e337b54b458a05621db5474b23b40fc220b0acff4edbda14f4	980
91	de231597cf39498221bedc697ec10346fbd9b1c7b04696251379eaf8014fe8f4	981
92	04011a31d5666d41fecd030fe8596d3ef71556ee3f03991a0ef6046fd1931de5	986
93	917c745529782e44e588cb615df3d1d5839d293d9fc9e7aa5baeca90c83ab523	989
94	80613acb7ebeb8004bb86995cf525939187f1dab300854aed21e109381aa91ef	991
95	76d5de74a0d4808fe5c8df59a2b87dd2e5dcc9c49553b81b83c5aa2bb2ce9067	993
96	b0917b42be17f60b0f9ea08a66334f95dccbb154ac39b50960b750dcb6618e32	997
97	03494e9941bd7d1a88f4811e8ae5cb4364058b9585d2fd5a88f1e9656bde62b7	1033
98	6ff37d842feb5a1064d4fc891c0855151f19019c24eaf5f3c1afa0f13ab8c2af	1040
99	d9d767e6a858fe7202f55c48fd628d91074f8cc8a3a779dfce389377dacb0718	1046
100	7b0351ca7a98949f4045f6b1576bf8515ae16cbd35f8f1103e1c9a48f5605374	1068
101	df7bff15d93fdf531923089004412c369d1006b4955a9653c82fead9717b725e	1069
102	57c5c0e2aea08276fbd9a5a14a05daab6eb5dd8edbdf4104f599299cd27b7393	1076
103	f01dc2a63d34f18c4b2b99553865ce521afc86c6a66c3e6c9e8926c3b8a281ca	1084
104	588de0da0636ad98ce6a53833d3432bf3ace45841bf732a05ac737fafd9cdf42	1094
105	d419e641ffdac599b61e41646eaa9f23c93dd38bb1e25ae59c9b8cc825346388	1102
106	f6207f04a150bca06c319027f54567b817dd4afa6e5e712000e3a6bc006f369e	1107
107	b13ebb549da3aba9250b5de3df040aaf8cf939e531605353dbb5dc360d13d622	1113
108	9ef1cb5dcc26a81d012c78bed2a3f57e0f0fc3b8ee0e70123b4f55b577559d3f	1117
109	3d6f4c0271bb8961488490a5fed0f83379a6484019a1d3cf6964827e39dd4884	1128
110	f9a9fe9c7ff27472b9ab929c86903d61c85364be1d74ad0d916402cf9adba2a3	1143
111	5de0d5aca3f57f5854343ea38e95a39d9ca0b87b18986c6414d58c3abd692ebe	1148
112	bacdffd57a5db18a54f9678cb1aaf4932b821a0e0ad603ac6339928c3391c39f	1154
113	60e8b6751b43d53c101f926c7da7a61757506386e36c616204e6b1f045b4c484	1159
114	7ecedfb051b8f897e2cd67c4043a81b4abf744fcf658b60afff44f5d90ed1045	1174
115	e987542fee6572d0e139341fd0faa2c02055d967eebabf28ca49bbf8826b8999	1180
116	160413b16e6057801ed2a18cad156b00a9f104a56140f56ed73170be4c7ee661	1182
117	22ce8d126ec0bd42113dde7a7541326668d1339a86e81ea90162c7a28a92bbb8	1185
118	378cc9e09d7324c43cf455cebd0573469aeef1360cdeeadd68876d9fe61d7b5a	1190
119	1f725cad74345d8dda27ea4a590746b56d46ac97541de03bff7068f308c58744	1194
120	c43f9453a9dd46dfdd24c0f368f2005860850c936e20c89c6e5b31a717a27ddb	1223
121	cea1b7d669ca4d3ba5ae70c1eb0d55378b30adfe28793d2f8402868f947a5eae	1257
122	76ef11c07e0237e8d1526a341115e3ba3cc421c59525c0976b21e72434c3707e	1268
123	c1b5e841d1d9891d3bfc08f376f7ce5ae5f90bd927589be2b1fff5102ab2b9a2	1283
124	513e1b0ad0ce43a80d87aea15b3bdd8daedcd0d7e76f4fabfb87f86ef2a12a23	1290
125	61c5df2455b8218b774856ca1792c6cb9ce3cec26c2642a6c747eb7f77c31d51	1294
126	f7a62aa3fc1eb8ac5d9796f3026fbeb33b1ed4d702894c276f7d0a94e0deda50	1296
127	28834fe93dadf6324ba69f2aac2c69092d7f0a3ec20eb80dba04034c74d9f593	1301
128	839448565358a50fa6ae872b8b5ec173926f0a2a8dccafa95598514968777681	1303
129	56a582740cc1fcb5850804783ebb1eebdb6df4c0c1ab6b05f13b6958b766c717	1311
130	05c624bca842210e9ccc94d25a245e90b2e682003c2e8c112d670acfa794310e	1313
131	44411f86b9fc5cc275a2317f29a26d83a1075fd55273ac61e4b9731f2137f1d2	1329
132	c7d2792f90ff004234fd88313d24ebb793f6ee78cbaa1db56ee6e812adb4b9e3	1338
133	f0c98cbcd67ba3f72651b64a11a7ddf004258b0af171f208028d5bf89762cb37	1358
134	c40653806086e2fc4bc6d0852cf343141f664d06d1f837c71e56d122ef6da70e	1360
135	6c4e6e1ac1d5ea701d9a8eeef6b7c93812343ad510437c09a19a589d094eb8a4	1364
136	f3c423648c818c5446ea74d4952c655085af536700f6419fb5148ec3abe8b8b3	1394
137	8118371bf8107e3d79f09a8f1c218a1855ad4fabddb7e00c08f152d4f201ebe1	1419
138	12399180ca03296cdc736b402461afbc9163717aa2776ba197a67291f0e4bef8	1420
139	b18f47bed0ddbd070a9080f1de90a43f4dbfe03cace2d976e6303628b9876117	1423
140	8d95fb44746c22e5cc9ce8b87ddd7891b0d96ce794aebd4b7bbc8e86b46e5753	1440
141	30cea075f79c4a2e3a052d0de3b0312cde6b5158f1749b4777c2e23d98c00dec	1481
142	918a324fbac3318aff159b17b868ed739aa5635493cb48794129064022de8338	1482
143	2a38b81e5f616bac93dd9d28f5bc2b058bf97629355f129a59be45036ef4bda6	1484
144	4d83d4468f5732f45ee35c2f6a10ed6f9653c14a039c6821969a6326d67f10e1	1498
145	3a6f4d89b67fb8326f8f2713400379ccd8309198e5a6bcf702535c38699115ac	1502
146	76df5ce74c50c5c2356a4b3f303e031c6c637e13e37d42f5fa5c30e68889e882	1532
147	b224a20759a06e6f5b08919d585783c01fe5bbfba92313e128191fbfc5050a9c	1534
148	be4b2b964d950ed17805e3a7911609e76cd1df213017641cb718cc961788331a	1556
149	60a4b4c04369df90d8ec241fe64dd8c9b01026c9c26b49b77031d09f93674562	1562
150	081eda80c51e8917df2869bf21c8099fce6356e1ab12330bcb8e8398504ce61a	1586
151	34e07542b1e4f9c694d0b90ed875e4c3b1ef072680c0add530e786b91fb61f3a	1593
152	a758da8587192ce03ad49116803d354dbb2465cb203cce56a2f927da8c31b9d7	1602
153	4ed54607bf4eb2f2517621ab6b9ab050f30eccb4a481ec248a50ae50912bee9c	1606
154	65da7b63ddc68188bcab2171369d9b404e1fa843c86a9cbdf020904f030c33c5	1612
155	de355c8c626db4a2ddc6423c41667740fbc2a3223f088c71325f2d56bc2c07c3	1629
156	09d3ca3432d9bf7ed29615e526e8a569123876a7ae3a75c6197b1c69fc6bfc1d	1638
157	d601fd77e29cbd9e7484f5aa0cc42c8e927f3072d9e45bf70af45267d59fe195	1643
158	da6aefa8b0e989bbc341fccfe4b438bb4e377386f01e81416c6bac2a19c2da95	1644
159	52e6656746f7e3dffd874f99d55feb9785e2986c1b2337e2a98ce20b647b365d	1652
160	3e2cc22f114da48deb8fae24af86a3766c5ed9351a24c65e840a3ab144646684	1653
161	92ca2c7f79a9e9a8357562c2de33feea16ca24f3f8044fa673ca189436482d9a	1656
162	a279705be83a6f1ec1e325ac2f2e9c1e580b6b5f0833378b707473bc5538815a	1667
163	3ba6c799c6426d4d93c9f5bb639afd3caaccbad4cf96e9bd0c86dbdf00484ca3	1670
164	1cef623b665b66b6e43b82a0fced0e25ff2a3064aac11a6185ffaffd86a66eb7	1672
165	9c8b7b8cb96043405b793327b6f07ee1875e87b66d51c0c429070f748f95b5f6	1678
166	4c048778eb7625687564b601e43491b02f3767eb4b240e1b9228e4e1272f48b6	1679
167	8167ea6bb1137e8c5ab279fe15668735e80acf1797ff76a6ed8981ceedc825f8	1683
168	de5f29776c6c2cdd1f24b4aeac8da66da9047921f15c8bae8d6e3e06724a6262	1702
169	189684b1bc37b06c1be65eb2161d9ca96bd70a78a0ef19035324523721785649	1709
170	e7df264a1d74e7d79ae4c89c0f41c01a189ef189a6cd98abd0bcad3fb431dcf8	1712
171	e83f9097bdb88f01d58b8150ebeffd8de97a74ca53b919787e54823390b48784	1718
172	1958da75bf40c915d9aa0af324d5d411bfa7d2d095f3740efe9427c5fe61f9cf	1727
173	24c97eba52ab2af073f4de2d36980e3279811c1b9ce7064fe035ef8bd3d565ec	1734
174	97bbfc58545585988d5805311e9ae0bf4b7e5acd118e8aa4952a47c3093a0784	1746
175	533b9be3371b7d647388e6fe1c75d03d40f58d1d5f6d05bf9d52cfb216889ba5	1755
176	34b7f2b8578bd9c9f0746281587f77a5853d17ffa9727c28f1f8333c900f7b1e	1756
177	f47eda8c81928bad77c53c3b0d44b09f906e0e013b837ecb2401244393a28218	1782
178	ec8948f7e378589889107eef18878393eed1a13746fa32971ceb77527dc76908	1786
179	66752e3df8c24af6b62b40b0db47ca5cfb0005c3bc82df67022cc61b957c6258	1808
180	28edf2c17706b3146ee9541fa08dfa2d6ce8214d13cbef12bb7bd30194537d0b	1814
181	7b59d84476e50650b7ace9b1c2bfc47d085a1ce15ea311ca37aa118b6025dcc1	1817
182	5e99a68934c87436ab2bfa1e8fb36a0209013ef6ebccb604e533b1ebd5039b30	1837
183	26931c78fd712ecc90729ad4e05778e1b54b0b64d1d971efa82ba0d3a8e9c642	1872
184	78fbae47703092e1cafef4ea966a050033bc3f0118751d1eeab17381ff9541c1	1874
185	118f098c6b0a86f6cc7f7c56b0c7535c8d14435061db10b3946abb64e839b5a6	1877
186	fd49090e862a497634875b1f24e9c13d0f6a9a58add85184f19f525ab440ee71	1905
187	a69687037c4dedba07b22c5595833fa9b83a7357e265ac99fe8ef8bb865a03a3	1926
188	945194a3e4ad2031284c91f39961e938d0c780eb808b32fa7d9287fb3caa1395	1928
189	0599de9d7165e01fe016c66ee927668c13626413ab32fa7d72f99394ccbd91c8	1936
190	03733fbc4cf05c1cb0a7dfcdddc6deb54b1513f610a2fb7e572414f6e83c612c	1938
191	568e0eb6c0b7d39921ddece63edd839343966c67075025c3f325a110f7a0e3a3	1941
192	a4a56fa8c3a3bce25aee0bf61c3426f50e7c7677d990b36a320902aa92efa693	1948
193	4993702f048df1946541c7c3238d99ef364c1dff07ee69fdd5b032b32fcac325	1949
194	51da0a88ed06775400b87d260feef5e9aade2cc64829fe93211d3d2ba103e2c2	1972
195	ecb8f9591d471b8273fdf44a1bb6fc78e18424cc7738bf49983712cebebffe8f	1992
196	7f754569015ed84e01ebe7c91c425367c741fd4988f8e7d20becb29159ef14e8	1994
197	afb638e931c80d57c3933ea0a565b475db39984d887a2a1a97c7fac29d914b20	2014
198	5b1ffca12c319ce3b1cd5c066e5c69ef5ddca529fd57fd8809162ff43804bff8	2024
199	e1df18330f8fedc0b545e81034c0c15ee3fa7ed3792a537b2e912a4bb884ac71	2026
200	e61d9561164317252127205383d1007012e8b23397db8d2eb8a1f81caab01edb	2027
201	cb215bbf507773633b71da868070bea47894b71acaf5a929f81c4ceb0046cea0	2059
202	f0a48aca22103b9ff872b41e956b53e1513c169dc39484fa5d91f436b853911b	2060
203	2dc38b06bb504f7b281ca74a710230a9e028823e332545f1b77d050bff947717	2082
204	3f92a943b6f2e2238746fdd864cb56f8711354679ca2b0113b26f0033a52a06f	2088
205	a88533853fa504fa224fd90ab02ed995fb66dc329fbf57ef9d99a80dec120f62	2093
206	6412921e957561598d1a06415828e2ffe25a8b223f0918dc3f6a269ee044a1a9	2110
207	b3f174251a274097de15a3dd9caee796e4e6e8c4e0479d84a259f4caec28f25b	2115
208	6e90c6577750a24c59af9508c980ab5b92758034e1ce1f66dcaf11ac8d8e489a	2121
209	17ac07b290938694d020a09367465fcc5465b9d0f93a455fe858e02756a95039	2150
210	39ba3c8c7fd295115c996e5f1a59e1604b0d14255d7c8f71f0cae69adea05d81	2159
211	f9ac9a79d980cefb2d3f8f91f578c48acb913f6965422587c4426eede31c09c2	2171
212	6d161039b746a2d544952f25939393166aadd2974aedf2623d492b674a2fd25c	2175
213	6fa8c07bfe014285e8ef4a062c2270228a78b1e48a81533c0e316617b67252ff	2185
214	c06c983e407ff827284f89e68361757b6dc755a5d8ce6d22d2448c9465772d5f	2202
215	d4b6b161d3550b488001909ee056578292c00e265d327b9a79a22f10bed86b2e	2207
216	e5b1d745d790fd6c56e9ccf33bdd435767633a24132698fa0da47901ce1ae5d2	2224
217	b939150bedffb0a9b5e6df6de0e1f2d736fcb848ad5bab91dc62a896f7fa6e7c	2259
218	8016787c70ab062fcdf266432c40152484d3c178d83f638005241313221722b5	2288
219	17fe201d17cfcde85d59045623cefd1bd2503efd01ceefb1d82dd7d0fef0ed2c	2324
220	c32209970beb1d3d0b9bb324a670db66e2ac7a2ad4bd1d404e7bf82bdda45cd2	2327
221	91c2c5c31126e6625a312d3cd6aded0c83871aa212ea119668812a00b9f49712	2330
222	c176a9202f7b9e26a75998cc0e561541997099cc2599d16bc691d31d727d6dd5	2337
223	26f5af5b0f0acabbadc53b0cca20918e38b50d32adb148956ff92725ed399e99	2347
224	fd8f67263ccbc1368dcd413fe8f9b7a009bd0065d631aaff837e99ba48c74015	2361
225	a072bdab285acc46b83c10674180f54d4360bd8a6e7a9995ba1a1f03f94c8ec9	2368
226	05775610f0e146cb092b746a43d81945d5b435f2b9890e449df31e9233765303	2373
227	47c1c7b8038277bb2963abdae6346fae39e14da757cf774180c59e8cef6d64bf	2375
228	d037246a2a9262266d0a5f843cf2e1c9a0d684571dc5ee0d69cefc731d0e78cf	2379
229	5fbf6c02b58d7b641b13b765cdfee5adbe01cc875a8c48c255ff9c964179cd82	2389
230	0be6336eabe40953c49c3f55153a95f6e1dadb437aa0caa6e34c0431d9bf0089	2390
231	204dfd7961f3390ab3ce7c0cc5aa7eb7476ad316e91794c0533981011cdbfbbf	2391
232	2f25e14a327b6c7ab085a2345153864813c38e9f0debfc07a26485d394126c6e	2404
233	3c498c760a8641e26ded1dbefabbda3be57d8761981000856b087bfb00e87798	2405
234	ffeeb5cb6cb8ff350d6db95bcc93a3f059d3c7a0d4b30c2962979db3471fc66c	2421
235	abcec7a3fa27720b4cb3991e949cc9bdf709bee05532445c248c590704249d9c	2442
236	d20b657ae129d82c4333e87cea249869fd546846cba82738ff51fc5da442c887	2463
237	3d8ec7e48c9cef395ef334b06ec7f5a0a039b89bb30f291d75320b26a0fae786	2476
238	46b92504b80b550250f80e7a114f433411ce896a22edb4cc4e1434dcc11a03dc	2482
239	1b07e85039067b033bd0bf2545d9d3712f7918dca869b481fa7c67d4e2fb8244	2491
240	da7f61affa1bbfd1d99ce2c617c6b35099775899bce3b53cef9e66a5992ba564	2493
241	f2bd63b55edefdee6655a9a3c0ad6e7303a0452a316ee94d42811b9b6686bd0a	2498
242	6bbeb9f352a71138704ca5d1df65890e73aa229e6e15b877081595df86adc75a	2499
243	eae7d1cd1d108e6bb618a99ddf3a1b3d8e9bd89f01eb0a57d99fee130b823f17	2512
244	7ca00e3a5fd18d070ed6ddd0e52f1c9d18bd18317fef1d1e70fb4174e9a2a694	2520
245	86e76154adcf6225c5c55146be504aed984cb62d071d0a1a6eab59fa7a468ea1	2536
246	df27579297867d0a6626754f065682a4bfaf5b0a91c75fd57852abd2e57933b5	2539
247	53fbc4781d94c8fb8c1f329eba98628960c5bd0023367282b47697fc36286834	2542
248	e27757b1c8ea4f29406b90aa56a03cac8bde54a1d52a352b30663f091e32af2c	2549
249	7f5ad995fc4de074ff482aa4fc0db0ee0ebe6cf6feec1b23c160bf1de51cb844	2568
250	001b69cca48aaee8e8b551d41de98b6d4728fb6d199b248a8fcac608ec5170a1	2593
251	674bf64352f2275acd187dab2b8c50cbb8f353f36dc46712282e8db1b97213ea	2594
252	329958e951b3b38ce6c0ced73e5cb6d4a13941625009498aa35a2d7ab981c2db	2607
253	80e7341df5c7d2aa44803d95ef70312328d5ba7f1ee4cb5c84b5c8390f3b8ace	2612
254	8634cb6351d67f1acd419dc0a9495952e02d9cf95ffd13c7256c42217c4a47b0	2613
255	37c0eeb9ca35005f17ce7a6f649d842d26f3fed3583842d8d56ebfe94762b9d2	2626
256	7afc8ce0eb23ecf2886cea2cd9f25df378811af89efb6053913c59ba3a8617ac	2632
257	2a9bbcc2bd2ec18caa3faf57490c6226574a69e13fb76622a2b0f9e1ecefa7b2	2635
258	8cc9bc0d03946f1bd66a051d491b4186f06ce5ed474371898db7aecac4e80d29	2650
259	c26c9b50c8375a55a6a1977b6e120ddc81d6c34cc960ebc46a3b984d8490ccb1	2666
260	14dd73dff7b7dc20c5c2242064e46497a62b5ddcd7f1f3da7ccdd0b268fa9425	2673
261	fca763053aed1f2e2da92f83e4dd7ddd9d69b90270e603db35afa8b1d8e893b3	2676
262	2667117721fb7b7b9711cb309df86fa80c1033f05a1c0d61a9c174eca96471ec	2689
263	4bb62baee9cb7e443c4517ac9c17a76bfab55c7c749d160c147bddc1dc59e5cc	2707
264	9d45086cebbeb3538ca9a9ec9fc439a86d5e713318f815a03cc2401c556c7dbd	2713
265	8a3712d92db0bf37a5f0b11cfd9030e32ef07d2bbd35abc3cf8c4d48b91f82a8	2715
266	6d0d538d4b073b8e9a9b763d789c10ef70cc6b22dfa52836f3f5485c88e7d0f3	2718
267	f1d42b25656e881f1cf649fcdc98e9a266897b7d698d857295598db499bf59b1	2727
268	7f4c6825c5758c7e07bf8d075d967a93db00ef5c628e802e1f22e25d15e2f1f4	2735
269	d4072878b1fc3d685ed358067790e4c8b80820e8109ccbb01cc568992d202796	2746
270	86fef1827b5b218d8236fad6c967a49a67c06885ab4b5871b67642d708a265ed	2751
271	833c021435b9275229d839fc939c242fc328348fdd1f222ca48f14ac76608815	2753
272	98d254fddf957bc6376fa56f81db5ac008e5d081ec48cbbb9947b379116853c6	2757
273	08e1568fb578498acd4d076f66890cc283d60ac36f303b58182fe519456af8c1	2758
274	0560e1217210787079eea9ad8bf30f97ba1d303e43be7b81005c577e37c84525	2787
275	855f9c7d8621245ba5dd94fbf6ba8f5223f5323537f6e8c385acb3c7fcdf2352	2789
276	72a44937c5aa816c9277454a92a25955ca50da4a053bf7f9407e0664b3ff75dd	2813
277	1ba3692d988a809dbd8bcfac06f8c88468985dd5a67cd1498365ae0d93a6e4c4	2831
278	1f530e13631ff5da684750588407bbde18bf8a2b97546a05a8734034208ee6c9	2849
279	6d65a524f12ce5f6c32c4a4682d3e6b0f9a5c03bc7bec15c8c1bdf7cf0006081	2877
280	46e4ceeae8c76291a55226c9001df21e90c32f267646847f3cf908204418d381	2878
281	cf5cc4ecbcbded9d682501e7ba707e56212e7846a9ad09e0d33964d55d685525	2890
282	79d22bfee16726e5721696a51e58fb9c61de2921ac4af413bfff00b87aeefac0	2898
283	4384435332103a93e2216eed80c3cc6a527e8de191f6121d68e8c1e5f2fb1057	2903
284	e4eaa4c425eda1115a077160c1feb86de332177fc1d54846d82fb343b94e51bc	2914
285	fe04202c49090c4c7e5629cf954c8c7dea44ba793f68e98bbf1f0d40f46f8405	2930
286	28c15d0b7dfb66d36429ff3ad2d5fb049b10d0909aa99dbc780c5efe38a03b54	2934
287	b37d3146b293e3a71d0a1176741e7d2f3e5ac21491a4577ed6dd7a1c89773fc5	2936
288	ab015728fe308f22a39f040d6845aea84e47a5e94439b0491093efe645df6d16	2951
289	00a53277c0f2d4ef7e9c98d605d91610e34c92bcb1b3a52f661264018ef04877	2952
290	5660c2b7e7e8e5e2c6134a51106f4a5a57dde7dc1e8b9961000fb05804057bee	2963
291	7758ab6c15b68dbf708f471d0f5150169e1eeba169b0625925de9a5c991e681a	2966
292	2e24e08fdc7e2281ad7eb880e9781e821ded87c035bc26ec2dc8e7a2f0542dc7	2980
293	a0035dfa2ca6a15a861117ace9185720c10a1670d554f4a9758226f306f67330	2982
294	aec9e6d1bb5464ed4d991f7ee2a4874122b2861472f52763396df8f3eefcfad2	2995
295	fca89141634fd4fdcc0060ea29861e6186811d00baad16a7f4aa6f0ff1f3ecd2	3012
296	cd76d43dd53753a05a6b995624260e60f21da906a51340175674699f1d2f2bbe	3015
297	5ad0583a4eb73c1f0323ad9788cd10166b3b70004f6bea22109cbf6fb01549d7	3023
298	691a7e4a0fe3c26db7b229f458fce5c5e6d52d8679524238de2fe3996bf72a6b	3025
299	e1a09eb9ec0b6b2f2c6b78340bf79430e1be286ec8365621e11ea6e0335fe06e	3031
300	b8cac1215dff9576324a0e4e2b15c6fe5ed6433d9b24e953df41c995d1e5d6fb	3055
301	194a6814d341272b043142a2469e136bc892cab6e4892733963d24d83e3c937f	3079
302	7f38f577970a42f1597089cd122ceb9bb4c76624908c54df471ec363e18c9962	3096
303	6a369fac02e707d5bdc3f94162b2541d571ab3b0dcb05b2480232edcfc7908af	3113
304	64128def7ac38888a9ed9d1f6ac291e89ef82097235887ea61855cef732caae5	3118
305	6a6fcecf458a51b8ed184c12c61415f7f64f3237169a32464e859e03a59f1c80	3123
306	5b962fe0df7b043ab369c7ba15791d260598778f593f3244106ae8a5ca7798ab	3129
307	d2488545131e05793c7d2311a80ea165b1633d2d7860b6947bcfab29e0620534	3140
308	d8a82009cf5d2e7eb14b66b589f3c83b8b9cd254040536befd794d033b2e42cb	3150
309	965625e326420d1c8cc852aad96529de9345eb29c989253e95afefe5784bac8b	3155
310	ed4a477d3a33d69dc29518ed54528a3ba892ac4c9301fdd704ea046dddf45f53	3181
311	ea8b5dbf62eac1494b3bd7a926a07bcbd4c364d4415141b2e972094ceff976b4	3187
312	4ff57589b01766bc35684772120c60c2050f27185a7d599af0c3502929fc1443	3204
313	7897b5df5a6c2b23839cfee7ea292dcebf8350be40c611eeee8414c98b7eba9e	3211
314	58d9bb630396e2bd28467b2101ce4edd562b2bb8b434c69a768b62057f09fe7e	3217
315	87b0f3ef0e0179af776bce883c25ac8cffe508b66795632def91644d728c5ec9	3233
316	cdba35eede5b1fe224164ffc4736969404051f4f2d646a2f795ce51dafa43b01	3237
317	cff12af097374b6afaea07de517d8e89ccf1562d3394b8d86a813e9997ff4512	3239
318	65c84b4a174a13640c76457ea598dfdf0d39174771fcd637c9df638d4517c929	3250
319	d0f90f50b31bf3523e5ef8c9d8d56e3bbba6dbe873805173ac69962552e8447b	3253
320	e1752ecfad77fcb846b837e9299c93061d652e25514e0bfff2622bd5835539ef	3256
321	9d9b4c1a3b7748edfa8f90eb9c0afec3c245d2e0af209fe37def3e09398aa762	3264
322	3584a4c12406d3ad8de2e87517b3e3e29379d6d155f4d2826dcdb713e3a5faca	3273
323	87aaf3c52adcd87169eae2dc3fc63bfef11016df22e0d6f3b8a74dad763ee2ef	3285
324	e8259c3b29bcbfba45942883cb06e187516540b5fa6e4fcf73a9c830b6f89a78	3292
325	c6d40fa9c3ba67ea8416c4b834c61721fb45a19460875b9f77411a2fa27a7c2e	3297
326	bfc2c60af5c51d52842475c5527e9a05c3b84c05b180bf4d0bdfb01d7eca8fbb	3301
327	15c71112e5a54c10385252ca52f5e56ec0c2b8399e3ae68e16b8a386d72e37b7	3303
328	8ea7dfb3ff8a2a4ac1c3d42db05b1fcdea37f2c6741f19340e4ee84baa1e23ed	3314
329	c475752fcb7a36517d69c0a6839d32fb60c8a06128b97b2eb49a46747427f500	3337
330	c9b04b1a4b7f135281592619d29409542318d307135d7ecfd750783cd38da9b2	3338
331	cdac2d4e0e1d6fb66b3adadc175a11502a83d5c80db8a81d8f3c5a6cf5420234	3345
332	9951e454ac906a31577926e7339c088e43bfa128b80fbb49c1d837f396d7ba05	3364
333	8011ee207ba278bcaa29e8d765947a28a5c5eb51033be372b94fce48622f674a	3372
334	1429a25a5649dc3210bf275f76c56c8aa9c49006e37d2ec4bdd377b4571730fe	3390
335	386e5a8951fce5725048e7f7534a15bd016b7e37f05bb68ef237fa8af953b8b5	3402
336	0a41a03fe656f3837aa74f43a234f7b78992b2e9278135ef188f76de52e4716f	3421
337	9b9e074de9d869daf7d11bcf81c8ed663c66a1957567bae1176747f8e2ceed5f	3429
338	31718dd038d7fc7e35d1a7c3c16a86bcad5b64ececf8d80971b7ddab781f27fb	3430
339	cb1da7d0ee74a771239dbc3a787d8e49c02a83d424b587bde2f979edf84832ea	3438
340	5ef44549825254f981e0586a80180fe5bfadc9af906ff9eede2bf50b79e104ea	3441
341	9316edd5b8870bffe5137a0c0a93fce361dba3c3d60b35a83ab6f851b4822dd8	3459
342	1546519e46ce978f3e905bef0d1161ce3c2eb99a86baefac0f022b7e3e081a18	3472
343	00349d16a0828328125ed5c210350d3f1ecc01e66167198624c9a6bd4a326677	3475
344	7b7f89e570151bce189535e28040f9d532eb5fd169fbc3b21a939bbaabb0a66e	3480
345	8ff1076b8ee557b0df2ded5511c129fd72407f30224f82438a3b8b10e77cd8b0	3491
346	8e1819768f4858bcb23bc629030fc11411bb7208b7244a476d2da0c9fa3b86b7	3498
347	7db2f36781c6fdb86a0f64effb017c13059aa1d51bf4e7e1835aec37bd919043	3500
348	51dbea305054d9b93f9a2e98b06fa105b459e8df73c1115b13363125d049bf7e	3503
349	621cc186a5fc7d7b13e03fff3022d6bfa9be7c470faadac036332773fa31e8ac	3510
350	e1a4eb2daf9fb88d0f22217530834be65560fda70c6d71bbd3bdf24a7762ebf2	3523
351	0d156f4fd82328b3b1d1f0af066a5e9fa571bd5c731a33de4bb6db11cffce1d4	3524
352	1202b5cecf5083252bf1bd2fe0a4052d076c4d2dae46f8cc005328976929fe3e	3528
353	62925c0656800213253394b0aa6a0186e5b9f6830ed46c9cf7b660af18ec2e1e	3530
354	fa8f1a814dafe3fa1733e9e3f22a3e969c54ee2ac5940eaa8af29160515c2310	3533
355	5002f1e40a93bddf0712c01b60e70b0646f50b0973f877dcc52460cfeace0b91	3535
356	939748207f15f03878a9546d0dd769a509520516de76ad4fa289e2e83e90dee0	3571
357	9952cb969e448ca6ed0e57c7d155c65062af0b742a4a7cdf5f7e76a3a4d8f7e4	3577
358	32590837f297b9ad49b1526f2aed1ebccc00e3242a2e39079923ac3cad61a475	3591
359	b09650841b2638875bd8e5e92e5710fc6d2a6bd962ab4f6cd1820bce825c014c	3594
360	e0760ac0bed332869b61efe0f1d2d5bef3a4f44c4757fd6a6efb27d35bf5bd5b	3598
361	347dabd93d8629b8e6bcfff7f2fbe4131bf03eb1fbb9a703471aa759a7e92bfb	3615
362	09f48707b4ba9a066e5c0fab4302d72f503cd43294b2942734601590d7a58d08	3630
363	079ddc3c453be5891da04184c29e6e4c6258764bd6fb8eb3a287857e9700c45b	3635
364	ed63ac6a900fbbf06966f9d8942507e7675abba284234d1a2021076a30f91e1f	3640
365	8be92d83c5c65e1434d671cd58995cc67d683ae47af0e08ded936d7ee395ae4b	3641
366	6db09f3b3e450767ffc333464913ec3d2ad4d97bbfa9dbfaedd98e8947dd8bec	3647
367	64b6392fe0abef71e2014115e4e0e7140976b37f566f7d848f76c37be87924a0	3652
368	075a8f0a947654ac537b6394812eacda671509055bc70aa299d3fc8b0730c432	3655
369	3609c987164da3d833ca2ba4b0aae2c4a0b91953096aaf6f8455b1730041fe33	3668
370	3a98f06e2fc577476301eddc6f3ba1338b9d9829394e34ea207a8299e6d2f14f	3670
371	54e6d686ea67bb3f868264f47b0db9db62939b148a0c0d2c2b558fa97a9bf500	3675
372	6c40eb49298faa82bd10ae80a3c65dd84c1ff5443c9f92d29e977fca3a8ee4ce	3677
373	fa2f4f6069418f8712f903def788af4628b2445cf2784dc07acfe3f76ca6468a	3690
374	5195db01d7db8fcfe7fbcd1b281e605a794d58ac7904d8df92e8f62c2d9f32a4	3716
375	20bc6fe3a58d34cce93254737bad76b94897bbfeb0b45ec7e1f86f9a2a8e63c3	3717
376	c7433c44ed43cca57af324f2f7162ce7fc7a9642a02966b16ca46f34bc3bb93f	3725
377	7821f25656e2e331f48cb1530745490e0c8aa57b2ac4f2b4a39577c11d00b22a	3726
378	94cf8d4fd1c8513baa4f31f23c27e89e453e7bfccdd8296c4889a270b426ead1	3730
379	41965765a1929d9040e34ccf613779952451021464e5745453021fff9ea62225	3735
380	16618e657c14f3e921de3c7fffa4aa60297391d9d116ade61b4f6baedb7b83eb	3740
381	bc8c1997fc47ab64594b9d2b0efdadb466603848e96d075cb546cc9247f49f29	3745
382	9551cb11c55f89c094801847f72301046daa09814e9be89a9d0f06f03d46238f	3746
383	61772bcb724daac45754c739a0427bf5482416099309535f15481846c85b6b67	3751
384	6af16e4b928a5472bb3d38708c6964f2d6290704b36fc1fd08deafe88522dbc7	3762
385	9693e2f5155876602be5dbfb588084b8400034c5c3d1ba19bb624c7a5f25316e	3765
386	47b42641b673630de383d0905cdb0a57d8dc311832d7e54f7aff5a8a1847b805	3792
387	b6da4870f4ec0048f2841f7d8eaf36952101496da4d1c6376eba9f1ea3eea775	3798
388	1fbe236f779db0700b6dc5dc878a9a7a3f4e193ccb5e1886a454b26f7e0109c7	3813
389	4b04b4b5471ca9a6542f4078ec193ad9c522a43a342a1579547988132d9d9ba5	3833
390	82bbb0ac9fd346d5dc2529bb0d83d6ef97c89e841403eb3b0c999328c9c2978a	3845
391	b5c70ccd8eb8f573981be72fdb8d645db9b06c14ff916385b731cd30fa8f49c6	3854
392	8cc2432b53e8732f5e29a5d03257f791eeda6cb25c17514d9aa71a5f1745d737	3860
393	9ac001d5e5c8d614d375b89e516742157ecd27353a0400a10d930d401cb87be2	3862
394	59d8edb7961ff9a8ec195b3990ef48ca2fe22a1c859bede7be13d5c29023e03e	3865
395	f97ba38d77a69edd436a99b598a4dbd27f8e6ab9eed2b066e47e3208146c4b3c	3867
396	0b1de4d5e7442a54aa05d27f6ca969fef3bfa1a4669ba718038ba3ca38556477	3876
397	413e8698c6c8f90dc12efc83461669ac2238a5c18a1a72a1005c67a418445d3f	3891
398	84455b34240886bb5858fb81e46ae7e9fc36cd78e14eff605aa4381c32eefe29	3903
399	9a91b60640594eec814cd62c0fb8065074e506e15f01931ecbc58609831287b3	3908
400	85db482a39daf2c1bbebf715c85054a677f1e17e88e6c44e0dec0096ddfecb06	3909
401	4aeb851b15793fdd95d623f79aa7b839bb5564eec18ab65c31742e465b6080c7	3912
402	f87c00766d2e3abacd7a3912eabadd8276f33df063af1d5c226a60ea7244ebc7	3915
403	7a5e74bec1e117bde712ca8cf6097ac5ace66e663d36f9326af1e75dc71b357d	3932
404	9a6c9d5205da16dc3501141f2e5b4a13d9f05b2d7d442160f1433037b514e400	4025
405	52b66425de68ca28c14c2d0a27710ebcd26f6ecc9dec654c129481d2d9c4537a	4041
406	7490de0f7f62e819e662d44f7144dc5a9b349ba41c13833f5d450808ff9a367c	4042
407	283ab0f8852b108f7e06c49efdc6edf7e383ebafa9db0cc05fdc4426468dc2af	4060
408	1fbbd7a38ee570da2bbcefb5c71d61283ffb91dd685839be04fe831609c3708d	4068
409	7b91faa600ab83e2c2e5da8f86d9288110e8379253185bfca90f48066b39f1ca	4070
410	e3df792fb845dd4267b310be7d546fc5d369cde8b652d02cde2271ac9cfdc122	4076
411	5e29e5cdf0ca40373aeb5e474a787c5becb0997d59945de9b2cea396fee83a55	4078
412	92c6902447e2095e0afb73a1d3f4d3a1278778ab198932197a45044f8744ce3d	4082
413	68cb33b5648f299f55f1f7b90a7f6e263b3c617d7be353d43d48a3f7f5200272	4083
414	5f30290191044d357792fc63807881a46f43a2e8530138e40ff63f4011074a5d	4084
415	098ce4cc81c409e75c7e8722c02821beff8d16c922e0f100e44920f95879b05b	4088
416	828f90d13034da13121efa9ca3e9a9ba6af5d76a633b59ab77dd5b9926444ccf	4090
417	8b0487dd046df5cb69db748d13f3b1ab470e2c656eb58161752d4c38b287868a	4113
418	29960569ee38f9b9b7bc87fc9dbe41f051c39ba6192e1158119c6c258766a650	4119
419	c7a1cb33b559244d339a3601e4cbdb7fac65da87e3cf6711ab01fed8b0929d79	4130
420	9c5660d5b3541fc6613cf3b05faa577294277b34f1e5ef70bcfb0ff3954cd8f4	4142
421	fb2c4966d094661533d281a6e3826fe4314b64b0f56229c51251dc7ce1a36425	4155
422	f1c34c1cbecf0d249668de918d3c7ed135b888a8462a0e745c37046ad88069fd	4161
423	ae04b8268276420f0bc93f42a07470f11b43fcd4288d310c81dae50a303323d7	4181
424	b36aa007fe9f2334b5f0c568bfb21726327f60498fcf1f617ee67c79558fb32d	4185
425	ab36c58c28324f88c16d42146697c1683e18da02ee10e5d062f27c7c38882f16	4200
426	1b460aefff9d2f29ac6e3faf76158fa1e982dbbb93ee59077ea08437e27b5c37	4214
427	17ca202c06e998da296cd0e85982b09e909043153d71119f83a40ebe889bed09	4228
428	40a8418658bfa96a2e7387e48f28fdb0cb510f7ee7e7d7bebdaf67b42f85f7ff	4235
429	1b92f87c9f1c29ee5309d62c145303f587905e736b01b053cbfb77b2edb667c9	4243
430	483a24d2bebe5d0e5169329f5148f8003d9f6b7abd9bb4dbb3c1b634cea05902	4251
431	5e3c7ea4765f6c9d3607dadf9553d45e2901bc0061df84842e0a66ecd8eb3ac5	4260
432	619ed447f6ff7db6b1d20f628438374d15b6a5f446b587c98e6d6ea12cf0e4f8	4264
433	5d2181d1ebdc8bc42b95314775893cbccf647834fa98288ee305f0351803a87a	4266
434	6b0fad4e32d895f1bfc0df5d41899124da118557a8170bb4ddaeae524bf8eb89	4267
435	417334a13eb193834a23ed2a9a1a47c599c5f59a1db97f37542805bdf090979f	4288
436	cfb073d2102fe72201cd2d6051a0491b660db2a01d88432a5b373d611d9f36d4	4292
437	bd87610975117a030dde5fbbbb0bcb54b74e4f6b74f4545fdb285735c3e3ce4e	4293
438	12de66d7e0cd75c8a584526f4d3dffe4b455952286a7032d7e6d15a95db15cfc	4301
439	e6cc82822ae4e4ae098b4f43f7537de72c5e266a44e9d82bef4b0958f0e28af1	4322
440	f3a125fa1b001884a9f49f75f010d5051fb33489b352cbc8713b0f5a2ae21534	4328
441	ee341b2424c36300632d7c3e1a50a2c33c436c20a01db2a3302fa07ec4619b23	4329
442	54c0293e6dd6e643d45081676f55e08f487a6812aea9c7591f09458133efce5c	4331
443	0cf44fd96c8cddfb0cde41c64f70b5e60ef8deac681abbb42b9042ac35b89ace	4340
444	2b799f7e035e892d6a44bb693314a4b6aee5a01934c0a13f7533c493b3ed75ab	4348
445	c7cdfb1df6ac731adb69af01105c6c9442096e6cdfb5c458ce7a58a790c55c15	4367
446	5a47b87f1ae3e214c9eaf8bdbf4041e8ab485d8d07f21c02cba63a55b9679a35	4371
447	ed0b9d8fc9d84a4846b40cffd53ed456de9ad017e9ad5ffd338e4dcbe173fb83	4386
448	072aaf621785f1ba9a0c7d47157e2aa3da715fdf8c91726faf89068be0433b25	4391
449	7135b6b548e5b2674bdb104b20566d0225e9d035e9451c86197f2a2ea0cd46f4	4394
450	46663d0d4ecaa83e954c0ce18ba0575322ba9c75462808d92455b590f0abfbb4	4400
451	8ee100b6c22cd76dc19e41e040138b2552bd0ad9e4e82d44887e887c03adba8e	4401
452	3ca5fbd31000a9c9c9e7bf131e768c6bb78ad774ea34b8cf67addcc93f683f4a	4410
453	a37c3450cbc37d5bb5d23f5075ce24f1182617fccf7e0a9e7443ace3c5fa5495	4419
454	c67edd35a7c18d8bd9f28bc39728738b00b77afab0bc4966dbd994e1079da715	4458
455	b23c1adbe78ab06da147bdd3aa1ba808279db37d4db6af133de160928e87114a	4464
456	f4be9413fb76a00aeefbc2d2da0fece5a22d6e7a0ba6145994faf5759101412b	4494
457	a7e9855239cc256a7e511ad7c06af8a215718a4c4c76c0dbc43a3a59a09c2805	4502
458	e663e4b54a1f6d38a47a4f9e409bcbfe4b0f3b473a2bb6037a78bd92ca6f4a2a	4504
459	a7d4c6db21ea99abfe205bc8ad1b0d4df42a0aa3764146d688c7e66354fcad04	4530
460	1d4ed2eb9d269572b8ac9fa3832b076fdefd78db149fac7491c176533894e956	4546
461	d755c1ae2aab15a63cbdbaa41a4b8a43e2cd339cabce011b1e08c1775864650e	4556
462	3feaa5cd290f2d1649dc4e3fc1d45db72c7327929cbea5bfbffee05037e6c40c	4570
463	0298eca778dfaf042a61e6030cf1a1c875cc6d17888b11e62a1418bcb650a6bc	4575
464	b46828265fa801deef87c9847e6ea39000c5bb8cce1afa95c6c77b0bdb9e1c0d	4577
465	69fb61e33fbc5c3122cfcc0b19dc81c39b9be57e85e80cc28430ae7ae71459e8	4582
466	7b400dde92da0f5ba73a2991739cec1ab8942cd3e53cb81e1bbf66fcaa576b1d	4592
467	42d38ad6a3bf2686a615283e4e55faf6fd69f5447ef2d422d2bb50b10ca15038	4619
468	67612de8c01aa1fae814a0b21203991c0d511ede3ba46646419f74377cba9f2f	4626
469	b8ec0991cff7537a38638a10260107a049832f0db7bbbc914127bff22b0cd0af	4651
470	8d9fed517a22275b6fa7e8c0a3f11388f51fec299e54d602bffb1b2e755bf90d	4653
471	1c1a58f55a7ff388a2da3bd3401335038ac12e327e8c8d091fb375c516e02208	4674
472	0d8ca33c82d7c080ea4bcdc8667ebf6526431910bb0012e85612f22f25b04c82	4683
473	e83a17666cd262621e3fdc403ed29b9f6245e9bac3c71bf177140c25b016cb6e	4689
474	fe5d22b195f058445fbb38999a3dfdc2089b4ef36c638af932868c6e259c112c	4692
475	6af34b901be2f546701743c311b03fbc7362dbbf751d7d7c52dd18a9e19e6102	4703
476	2d2d3b809036db78a4b6d4a68b6d714e5901eac19444f565fe7032fb6d50add8	4704
477	ece9438219d317c8c6cec1e14d93e667e523300e0934ee02db93cba2996276d2	4706
478	024778756d4dda908f132cfb6b8241f148c0cd82570a248ec94d21162d8a3a6b	4722
479	197a1e8650613c052346868c5453d7ae195a22e7cee6542bf7c9480128d7618c	4735
480	2afcc74a7e427d6b58f1c4ca00d32a3833c80730d280a05280e67348ae7e30c4	4741
481	28342d2e11ab1d3ba7ed034c29e4695898a09bcb9f5d39476d0b6c1204ca6860	4759
482	b07d034e20408a70200ea2a9c9202e7f8ddc542c482e039a479dfee14643e8d2	4766
483	94844a22d6bae90afd468a9f3fef48dd9c408f40de1de1ab8d470f4eb503a9ca	4790
484	ad6f8bdd8e9f69a2f35f7b117dc83893ed87a4b60530ec59a5379619c842a6ff	4791
485	b1e842a045e3e4c8f8f562053ebfc2bea806ca2d404d24fc2804505612de6283	4800
486	9a5d3c67b89c7172804c38a66c4983366bfcfff2cfa9a4887a7bfa80138b8510	4803
487	c7f918bd87d391c9adb6162a85b4cecb66b7219edffd7d3881b6c53d057a1793	4809
488	4f21dc493a765d827db93d2a19867a37102695e37f61a80501e8b4ccc60e138f	4816
489	e8792e3c6db71db8cf31877116a7283bc0a305da2c4ba9ca8a7c44f6d97ad4d3	4824
490	801c2e41d2372e0f65854add254418644b6959604843cab008c15b3580894c6f	4847
491	23039d4d245f39a66ea2d12e24c00cf4640ea60101af29062ed4b05e7bcaea48	4876
492	edc2ace5a0fbb65e0339788c9b28479453216c4d6d959b85c42e9beb92798e4e	4877
493	ac9005152e17df1bcb15d49ea4c2aabb30745f62b524070292ef73994efe58d3	4901
494	8c45aaf959cb549c1afc02d23a01ae4adfa02ef8f12ca3a172716c56c24dfe55	4906
495	807bee24d5a76c6d04e186b65f9ad4b00ccc19249c9885528b418b2e272c9f49	4907
496	5a0352ad9b274dfc40adaeba09adc06fc3bb0cf7c41ec6d4102af099bdf6dd2e	4918
497	52f82b09e1d042cc62a9cf71d239da2ae247eaf2c5e4361982e5546da2d33225	4942
498	fccd98e76dcc35320ec0f926af0f18d82850a634e8c5c59fe0b92022464c868a	4953
499	1e1e15209e60efcd6d51deb375fb437a16a30e55eb623fc854a8161d9391b799	4958
500	3147e9d0e968b8f62214238e73e8e0ba9375050d562a49cd704ad4983cd2bdd1	4959
501	ae9a6790c92cc0cd9a9dba37a205bb0c75e8a1c3d9e6465a4fe81b3680cf411f	4964
502	673074a7a93698233f9a210e355042b0c56932c71151e30f01f6bf0f9bd37e38	4968
503	7461e43516ce9f98be2524a3a99ae3b50e4a09fd0564138f4147e447cfd66cc8	4974
504	85d04d5903b9fee24476aaabd06c8d1b74c55077badf6f652cc3e90b818ca8ed	4979
505	16622c94183f5d1c8176d14f64514fa9a0e1a0b17d7dc9f18246c46a1b5df714	5005
506	b73a33e2a1ef782fa8c9b2f4cae06bc2fa1fd1a2881a77b1b4b9d6a9ba813613	5016
507	611c383907ba8b16f24bbedba16c59cb76363a00f3fccde27dd16e621cd13785	5018
508	67a6e9e4b56a57483646c344b09f0a6bb7d82f1f487e3815e3d6dbb2dbe9f94c	5025
509	b927b7888c07f3faa5f98a248d87690fc6780392308a2e2cddfe090c8749800c	5035
510	f96a6173b944ae19f18764dc37cba279bd6565b09c172eb33a8ae171bd3e9a2d	5047
511	e28a66bd59c841b5a6403b1cdaf68c4841593eb60b66c98a057d52f282db30f4	5055
512	33b5c8fe3fd8da9fa3643c59a92f728e40a9337ade11761893df6bd008064505	5063
513	bff1a984c827f7bd955e21e5f3b162da897a4274cc6ddcb228b868a54fa5865e	5079
514	9e6501987d1a2b84cb1159dc6cefc596b694cb8f0ddbd9b3ae4f834a31121321	5090
515	49222eab3a066655ec2a578c50f68174e482b57f8e8fc99cd9d0c34ff352c2b8	5091
516	cbd3e309f7ea787e291277b9aa88701f0d081d599ef4c598925de325ab5a9c70	5105
517	94d48833a31d98d01b7781ad1da08106315cbef80eabdac24a754a0444c61036	5120
518	523c31cd75692444d4ae862769bb2e2bc2b342128f499efc7ea9e6132a2f88f1	5123
519	b421df23967e85e9dac8131677c5366e24b562c67d8db58b94e5984b4ed74bd2	5135
520	c9c4004696fa851fd29ca785b5d333aedbeceed8408302b2daf54ae2fdb5fd8d	5137
521	f80680fa79762f22a3dad84854a053eb9424a77a56227e392a3ff8fc33ae5702	5147
522	7fe56ef3e262f942fac44f8f7b532788503e55c37d01684fcd027d7c3ec3ffef	5151
523	ac0cb67ce6dfc2ea833ebcb3bca9534e44d29cf3586541fd496a9db84bbe4a0c	5154
524	76826fae62c1c76ae1ec25f8234a193356b3d43323c9c2adf6e56b2f0aadd98f	5159
525	da2f2a07430f3fad1cefe3318bf091af6c91cf3dff5aa3e8b4399e09f4e91df4	5162
526	45df8488c20107f9d2e694fea59114c7d34510ab2ad6ba8c363f7a4c2310804f	5194
527	bccede31df24d260667bd438b4cc537b913f80881f23d670196ab81cafe69565	5204
528	7aa357a97beba21883587c6c89e677c8d76ab84a880793933ebc9a90a28dba21	5215
529	ee64d7dd408c7d073cec654df1146605c5f261475bfef30d14d7f9dfcb9dd698	5246
530	5765d9cf19f7870097d29740dcceeb4d9ac32e3826f297c4f98bf60c0b9e5429	5271
531	a03080dad47fad19bda04ab478623ae248024b62d19930deb230e224001658fc	5275
532	47a0d7c170137987150effe026191a00d26cc089e826e74389024a98b50f69ed	5290
533	f0ff11a3816a4713f79395110bc14b6f12549f1dafc9971d230df662680054e6	5305
534	dd61acdbadd117d7247a66a9fe5abd5eeb5542d01f9f3cdb7dfb55a9f18f3c9d	5310
535	c2481db6084ea1b6b10c612679ffc3c4be1752f63629ab1e7a2a81d31d1f126e	5323
536	c0af988ec1cfd2a1cbbdb6b3382f1db3f5cc5a04fd7b82c62f1bb9977d3850d9	5335
537	93e4a117769aabb350a2a8243fbf789d7a6a99d23d9eb4488119e9f8987e33bc	5345
538	1c9f743eed359e617e2b37191a838d70a23cc7eeb33d71561f84c1381887e7ee	5350
539	03a7778bb30179ad4e0e6ba21ec8775658cf336f27fbd0c77eba26eaf06bf266	5351
540	0be330e8ff3645beb48936950e9ddf803b953caa6cfbd5ee76c3e892ec35d9dd	5363
541	86b656735ab84fefd9e7e514496773d06b2dacd282e7256a1fa2672644f01944	5390
542	989f808f7b01fb879fe0238c1f205b1cb70c30df9bdcc13faa2e51d3a0fbd0ed	5392
543	2cedb4165e62ccb687f1488c9b4f786aa6b2b5abeba6bf6f95a40a9dfae02364	5410
544	c05e006f4fa130be0f854824b5b537b45fc2d210b048fe4b2b792122169fb1b6	5421
545	69e4d479851c1c618fb742687f58482adcb6a00f8bb9b517c80b9c59fe157a9d	5448
546	99779eafe757b939e451ef24384ae4f727f411c7d04c9e34bcddbf1ecd36163a	5477
547	ea5c5c21ef8633c7ce7e76aea3bcc8b388997796a416a918ee1504c3073b0be6	5484
548	556532f6d25a6ad58df38749ed779bb566c00b31161d7cdd0ce78ddf85bd8836	5556
549	204e69d19f9950ffb9956aa5d55b4613f3177594ee6ffc69635c2ef669db397c	5558
550	0e9d301c28a619ab4be1d9e33e92b520da02d820f32fc6cd5e5b1923b042d3ee	5567
551	f269d9059c70c20795fb27209c82ac747159017371355ea9775af1c4920c9b6c	5573
552	d2d3a3e4b700434f0d287ff1e5cd61dc488ea8fba1941488909aac487d1f82ef	5576
553	fb0b5585c1fea3fabf6d79f168969173ec3e664dfb2f1784dff91cdc85d36f8e	5629
554	4a1975e1a9dfc83fd5dd0a7693785820a5aced1b5f01578c2eee68e22a39aa7c	5637
555	f7ffe6e531f6d43a5ec35e0be84aa18e3c412f53c3838c1446eb9ba98b49662f	5667
556	ee95b73b21793cb3a54fc704d321ad0e3ccdeb1d5e4bc320353c0cd4599e9191	5674
557	2076c4edb79285d02815e4b75f42a9c3a3b6faad9f8129444a3690aa932e44b0	5685
558	3819fdb8252f6d83ee2317407daa1c060ff87979df76194a58f36591b69a09eb	5713
559	1dfbdfa131d1bc68966e5e73484019be2df165bb145d520cacd9673ffe0c23f5	5714
560	1747cc47f38a73d622e2680ecc7ccdb8e798490fcf706ea04f60067a4875da42	5719
561	c1ce55123e009ac15195f271ec98ff48a72d7004b40bcec97c399f1907f8d3ec	5728
562	4953cab1d9d830ff5a246ed88ba8fe9f21e266ffc1d46d088ab64037aab8df0e	5736
563	f7c28c88a77be9dbb28b375f271a5aaf1f16930ed13b1f3c781ad1556459fbe7	5740
564	8add775586460deff9653369a6128ca2e794416fefd7f4b8cd8be9f4a1c9d098	5762
565	32cdb9186dac820a2850b12a1a9cd7681e61a8d929803a873c391efb42571370	5772
566	7d662352cdb5fe6d5fc2c277a737deb1971e4c8fdbaad8d00e4547cee3df30f4	5792
567	1bc228dcca1cee4ddc3712bccd95460cf1f091827b66c5e03bd14b595cb40bf2	5793
568	7a046efc1384bae25708b9a8a26b1d0a15bca0cbed90f3ca834c278ad6a4687a	5794
569	9e7376e01a0e759dcfb64b6a3ecfadd5ab817d37e911222c2fc5dad48aafd4f4	5800
570	98099fa40738b0d1955cdd2a74e4177669fbb31c738930b9149028318703d8d2	5810
571	567c5edec38cfcd38d16a616ca7f342b2ca278eda267857c57919f540f0da0d8	5817
572	94e9fdcfc0bccb35c3c3fdcf5608b18aeaac11ad3dace1a94d74a65290d0ecf5	5821
573	928d3127cbc12e40d96d68f18bbd56c9aaef893477adf87220f0b28c36524c99	5830
574	21116c4868583bb5b5cd8fa1a88e3c7f54bafd4a1234aed8f66b2569e33198e6	5831
575	547aaae8fd66ec8d8b39d9eb1702d093132df0dbcb4b4ece03551a020034b4fa	5833
576	6fdc0b3992340c3d5ccea66cbb8b18f6596d0f1c03504cc0cc82f6250931c7b4	5839
577	4a8b47a99c3e13de8a2f073dc45fbe59b3db665eaa923155f2015d5f9e6472ab	5850
578	9864d226ebda2877b71b670377c748884dd3678d9bf674f2fa52e39b146087d5	5865
579	e97536d302057ada293fb932df5be1d54fb14757980e9702c22e5aacad7b0b7d	5868
580	91d04cfad11fff499b1d7843151feeba3a8a0285c354337b44f67ac06b40bf85	5901
581	f90d1a1ea8abaae1795439f5015351e7b8bde9ac0052c8a03f8d31c27a344506	5902
582	a43c2f02f8070437ce86503011947c472022b7e4b66349404334a5b69cf9559e	5905
583	6a5507621e0832240ef25a1fe074b3fd903daec12fcab5c52f850f1456301a90	5909
584	c4d21a5c8132297b9d403b189961a95dbe9e39b7fcd3c751cdceea292827d25f	5926
585	f36bd67d67331521045d1a7c259f0c8f151b5f50a30c11422b9a2b45ac7a655c	5960
586	7d03ff9f7992cb390f553ae9ab4a4f6bb6e5be4eec8e1e1b96f6a847d1b6f88b	5971
587	7603dbc2d2188c227ffcc2f95b02a1090d50cd9d2a9bf1ffad261cdf57c1f8a3	5974
588	56dfb697d1af1577aa42b2e665a1c4c5499a0f50e3017bc35127e8f342570d3f	5982
589	fad4eeaedf43904995562213709689d1239fdb579023f19eff4876f7862ffc36	5999
590	32cd3d023703089eaaee67a9ab13eea560acb751fa7dd75144ae40015fb4a063	6021
591	e06483d3efb684f87e2af8cc5fd908b93fa08506f2f704ba89200dd9eac86b0b	6022
592	411912d990fa192538a637c20670c9c5d3feeb1b98c90893d851a0e36fe57827	6042
593	d5454d30fe3a852a15f0cc901385094cdbabc78db101e13d99aa347fb70fe492	6050
594	f37aa36644987f65ef6daa4e45829fea113c6e22696324280606bbe9233ae0e1	6061
595	6b276e5c833ed9fca26cc71b38445a9c24a4988767166230ed9cfebe87443abe	6077
596	a5ed9e2b21fabd20f01a4f03b7bb6133cb19f4f81334821ab44ed470d9e77f02	6080
597	9e0cb09f40d1c2318f3ab3d8698e927b30965c1cee39923b323d25c0165f8227	6084
598	2fd049def6c3bde38af110c26667ca0d4050e39738796a326ce3efaa257853cc	6085
599	8f5bfe3b186ebe74706b7e14d6ad79173f43e1cf788bfcfa1dc28c66d51692a8	6086
600	e8c014c9d6d5e27e6c7e78f382dd2a8010095d85fe831100fc2339f3efc47dde	6116
601	677df5605fd3c4a10c64ddd258a1664024be2194e608d6f18234a84bc8a2cf77	6125
602	b901ea4ad41d5d7741dcbf76be98a80d068ba0c35b7274bd14c2b8b4207c7210	6126
603	7bf83934e60ce97ad4e44e7b6bd604dfae70d14f55a690da83981c5f592a38f1	6135
604	30352b974610b7f69dfd3928996ac57f101e9f41d730236efea995504ee64d6d	6143
605	ac9252068d406dc8e976e7ac22b366e757b4d426d7c36e7ffc7186f3b208c3c5	6161
606	40ea27cec781ce21deba774a6a53c6d8493e8a789a6412dea6f266cb197b2200	6183
607	7d847ae6d6b45e955e4a30e5fc4fcb5dbb2e3f8e7fd2e45dd8d5eae2fa9beca2	6190
608	ad1fa8fd62716f02e64dada795e75391857f292c9d25eb0d04aa62acc3dbb5e0	6204
609	06e867e4361aa17e2dc7aa6803c564f986653eecc23285b2e4e5fd0d55f37dff	6206
610	3435f0cf8cd802d1a7d5c9e2cbdaa032a08e9271de0c1f36740a691842cae892	6212
611	10646d5394ac4a5c84c62ce39fb41a1339647364e7b952edd781d4c85ea87c72	6217
612	425b3463b6cfa06515a2c86287c789437ec9658a15ee962619f8acc6943c937b	6220
613	2f893e6b8040b0faadbd1dad81cd72b3ad5b23cb19c2fb12ca89583150e9abb7	6261
614	5b8e0b0e54efdd7ce7da87491cfdddf58deea9f36256c57696e3fa18fea62c95	6268
615	6ccbf930833e80d50f097b764a917b80c795636b54272e1a4e2c5d4635c689be	6294
616	a39723f7ba1a55b6154dcdf84fefa47600974a18e7856a5b8d95a235e0a77dbb	6303
617	cfc92043bffe8d973d54b70f7e3d6c678f764514502653c3d3024170a3e4da5a	6306
618	9fd1eeba212a8f403badb3105a981bc5701ba74e85d237bc19b310c5b66c3708	6317
619	0ffbdd471bc8a46cc68fa7aaa1c5f0f0a218dbc90058c2cc6bb5fde31d048e52	6324
620	261faaaa37d7fd5b4fa366b80e10692ee2686112a4c39ec704fd2322a1205cd4	6351
621	caa63516ef850fbdbfcf687fba40201e86055f0640dcaa1ea188451e64ba71af	6369
622	eab6a51c79986c18be6608240b2e408c5f1bde2feed1f2d08214e71646a9cbb1	6375
623	70c94aee2428e8dc6ab1cf933626d7fa77acc860b70ccd235dc99c891469e6b3	6382
624	5c0de702dc4cb2008631c44a359710b2212552dd976f81475dded77e8591415f	6420
625	a8c6510dcb5a8c54740ca63f91c2dac4106be51a49f6543a2c1f7eeb854438e5	6427
626	1d395476819a4cf23d0ca5b076cf56e2e6e0ce1089cebafa29b3252b4a8e5732	6437
627	986efe227b9b9d4655637e46a2fb9fb7c0705fb411aa36a0d786a16cb38a1878	6438
628	f8b59e0c6ab41ab892801b4ef4d6278886509104e2357f51200479ffee4adfc9	6448
629	e0c14df8e6b2ad5f494887167a21bba29a28efce265af369a37416ecee722f0e	6468
630	43ca8af317db3db0e9d783b9fa8ad29784ccb86a847eb73acf245d831ffe50ec	6482
631	eaff014b9e5c92b19acd42c9aca9a41d385fea35b78f3f9943bf4800c5ae55ff	6486
632	64283d805fee8ba3f7a3bb15afd663ff11a575f4c3371a107bd89ba1ed502451	6491
633	e46d486ec161ec3c431a4b598e85fd4ed4673abe9fc2f560d4707d1d05e6a28d	6494
634	335ecc17d26a29f1333c6e3f1b2f5394cbc1fadfe7959f083c0d5b84e0de1d29	6501
635	93ed493c24a8e183b1b11843c3314a755cbba30c8bccb3ad1e765fa4404e8ae7	6503
636	a52ce7e8c11a72c096d42a20c2b87d33122315d25c4127e6bae4924683a79cf7	6504
637	e1764f6662c5723471498a921fbd6c9e9aa8a556f44d98176bd7ac5de31b7f93	6519
638	4e46e8d3d9b32d0c88cfb29c3a9505a5879c4a62bda252d8d4890aa648c62a9b	6554
639	44c0fafbb527ccd750d5fed4f6d326bd42cea4813b66373b8c92526084049479	6577
640	daada5dc54d164ab961afd76d89fe43c3ab92a9fbc03309ae3dbe20b50303d16	6602
641	329b262865f4fca6688a48e9c002fe4e1a2e6d6b0562feaaa4928685c8652a44	6624
642	5c139407b6f9ecaba6b3c81406da89c755741bdb3b16ccc88eba35681e64b7e8	6642
643	f3b40df6e771ba56cfe426405f3fbe31ea788e4abdc309987e90270724a600b2	6647
644	43d6321cb05befd888fed596f19e7145dd71b8200299fb4d9d73a32ba79fcb5d	6648
645	c186ccf09c05a4aa41605f71ead4a582f4d3bbb7a685392629be8d99a2cc90e1	6655
646	aad8a64b0910e95abef47f3e625d3171635b3788e62b2419922dd5b18b6f8c9f	6662
647	dc288c5d0cc4954ab1c211be3491bf59e83b11eb6d614770c0e69b44049af69d	6667
648	c18c9e0347dc380563f1080c96e30fdb8d1b718ac2504abc6166d4d1f4f4499c	6675
649	0b7438963fe9420194ee5d558ce31f07735ed5dea4c12d9e377507d17231298b	6688
650	1e61bf9d1c007a7607ddc089070764b576eac1c98a8e1d8597ccdc1fe6f00bd3	6698
651	0e016f3d7adc5b375ceac4ea41efcf993152f86ffcfaeff5f455161f2a46eed5	6699
652	3d2d0250bf589b13818d28d53d4771664bef33530d03b82a2e7fce46d23c4d81	6700
653	29d2da066ce3c1e41f53e59d5c0a39464dd8eb547650946a099e37296f9b5cb5	6710
654	36069cb5712e075603ff9d7f135d2171f8902e835d1e655140ea0a7991d5f861	6747
655	2812dbd41032d0c0e6b42022a4b3c16bde524261868c7c43183841c00257d3e4	6753
656	d27c3e5c23316c76b3c9d8a4f402a237b9f49f22ebd93f8e0f60bf2dfaf053c1	6756
657	f6d4a2be083b7aa9ed0503cb0a384c2c7695e402fa5cf2ac83659cd5af3f3098	6764
658	545b4fe54b3fc406433cacc979ec5bec8beebf8a91d38a0b78391ecf3aa1400b	6766
659	a7ec3e604afdfd6f17d9c3047880452982895a71bf45496bca42e5c8879d08c1	6769
660	0d08f4c69ba408227afabb0b0e488a76b59675c6edb34bf3e04e46779480c8aa	6778
661	69e8013d9beb31a919693793ff0f55e9d6393b2c42a9d0188cbbfd24b8a9fecd	6812
662	261c4580c506ad577b5ce9814471019a418946a57972af42546cf7c866f892c7	6816
663	bef0c9203d62123e285efc1cd06a709728550475bf7f294a7428a4ddae940916	6829
664	36dcccf99e3338dda71b101f9ce514ea011447dc56e6da7c3f30cc403e1d0ca5	6838
665	51161d0804081d59a14bd5b7324760de25d1898cf4a18a8b7894ad5f5d2eee75	6853
666	9d823c080ecc13cc609b70fdbd49c120dd0b5954a5973433b018ae981ba379f3	6865
667	ba3d7900255cdb406b2aec1f23bb2853988180264074c5a5a05bcc18495e74ba	6872
668	9a0be995625f22b7e64ff16eb1c37fdb8b1877c21758d8ca7c1547ea858890d9	6879
669	25bead9ffc76612ce179616f03912fbb36fa6a648dc4974d98a27dccd5628cc7	6883
670	80832a7c99ff90164a060de8166a3f7440c0b5e03d682f3da7a383ca457a6a13	6911
671	459f622106a6df9aae4afc5c386c83916d9075dcf5c1fd3850f148acc3e9bb3c	6915
672	1f00eec672d89e29d0a75bacd72b6166fb70b6144f352ae1c544a9f27e5b8ef5	6929
673	254e1e53be29b672a8be7f2b1f405d6d075ec88bd4a368b57991ea2f36a258cb	6976
674	de94e3588a768949d6286278f13388aac2aca520ce3e6f63f3d77c622c7c2e16	6977
675	22f8af6b7f3c5182146f28c3874825c4843f6b3719e98221a95630b8fad3377b	6982
676	f83a7d6ed3e24d632f5f4d649aef8cfce75a1f9e249085562ac3b66d8b5ebb3e	6988
677	67860da4d748efc378710b95883be6f230ed1653ff14ce644628e91a7bd75972	6992
678	838434d2088a4db5ae9640478e13d1ec1c9ce9c9fcd8d68d7d0b1309d707ef8e	7004
679	8dbbfc288f9a06ba3b50c4b77016727f736109f4f6aa079541b1cfe8b56d2a57	7037
680	7427e3511134043265ea192f6e2dac2297de078c33dd5aa429e6dce2969d6fa7	7042
681	74dcd6ee3c72b67c6384ff3b4b0e9562e63a12e67f14343c1b067a9402234694	7047
682	3b7d086d0fde1680f744603c83cf951220aaa966b4e85bdfc04cc7d029b1a46e	7049
683	148c233015755098d1f8a7cd5ec65b41ab4f519adb3beb1dcfda9c1619de9c52	7060
684	6fb5439fd21f8fb253f6052bbde24649d1f63b1ca297e3b5133ccf25b085472b	7069
685	2ba87822bfdf34cf0c87434893fbe776752a78b8c0c41a0ea131e3353f6347ac	7095
686	2fc5c3d91ae0a771fe270dec50ece25f465e404411e5c8a125b9adbbb2ac7ceb	7115
687	2ac25f158fe1a6fa17f957eaf3c1785c3b6d8b154b66f54e57086c45c7a778d2	7126
688	74094a4ff3a9fd5ffb57e836f438bb57c4fa42b19c6134b02f3773169d17115d	7143
689	18296e7deef3c35f22c8e5e33231db574218c6af31c31be318f3211c688313f8	7145
690	e12312900a2a33747c3e555d675723ad444a537b5e02f1fe273ba6d8a134671a	7156
691	d524fddfd35b272aaf2a1fd9f4bf72d83c81627d9bc8bfecc24eae5b203c50c8	7174
692	a2263d4c590feba3e5bd5a1a5d144de0e0e58bd5202a39e315ae6ea506f0737a	7183
693	211e6d8ed19e59561b0dd90cea4f5193602812ca8b63334bc884c8eff468fe57	7188
694	6fd14d155eadba4fa092794e15bbffd687c4ec55198e37026b8f824cf554ce59	7195
695	23e639cbcd221607a9e8752b90cf5a0f2bddeee834c404ef06122ccd00457984	7196
696	e0601a054bf6fcc7c100e7058365e252cffc001594361e9a10e86e8de644553d	7198
697	18bcc9614df3ffab935085a120144334c7fc33be6e7f866ea42995819180c64e	7203
698	decb6e3dd093e9537598d89d00a4c37e4acb9f5a91c759eab7b7e05fba261954	7240
699	a84a86adca731173277272bf88eef35e149583df9162dae4785256f503b8862b	7243
700	124051902c46082c09c2b9332421aaf95beb8bdab904a190df123783ef9cf2a0	7247
701	5215c03f3090b56ac3fcdd36c4d821d3fbd67d4beca5dde1e2a7e6b319f111c2	7251
702	7a8de18258316b96b269182905c4255825cd0d5ae113a738271ef9058eaf23b5	7254
703	ba82fb875c6b6e977ef43f68f0927f097ba838d6fb1fc63857503caf97354091	7270
704	63f02646d501686ac1e4ea4ea825762b90cb895df04eb45cee4d40a58ace52d8	7280
705	dd5a44b037a1ebb7f3946a4a06c6e817a434f180107219e43b6aa7e48816de45	7288
706	3be578fb5918b88ea4156a469a18883e806e9a4604744f0582cd01ecd12d6095	7295
707	2d821e9c04602311c8d77d2dbe3545995f21db5beeb04bd8db6e9bc550aa8bff	7356
708	241cf6340a0b1ffc703508a1c78a0d7cafcb67ea0fdf63d4fe93d2c913f9421f	7363
709	b190a47c4ecdd05e04d2e31e13726599e018f1e555528f8d42d864579de45d5e	7365
710	9da848cf06936678ed138d421bec9024de90eaba23c41711d8aadcb3b63a98f3	7367
711	7c24a734cd65f53b79dd1d0870da1e9250c4f9b2f42f6bcfa7ac37f3b9c94e56	7369
712	b0060d187f0f21057803530d07c1cee809b050812ed0f5c81c8068aef64e744b	7376
713	a67c79c9776e7421ad1d6792dae68f2c826cec9826ddf5240216fb6eb6e1470e	7396
714	d492d1b5b8994aea75678ba3e86842351dbf51e00ba6b4ef965a5c5e58f32266	7403
715	275235d6e28bb7006db6b704f6b121d436b9a2644a8cbdc26d96d7d62c9a700f	7404
716	16837bae96fb45787bf1a6d8ee767f0b507e409303290909ee32b65189b41098	7405
717	f10fa1d185b8f09fa0ba0dbeadbeec1d1595e2df8770189d030962cb519eb9c7	7408
718	8bfeda7f47fd18f63023e6493ea5f86ab5b171b8050bbfd33988840dde273976	7410
719	74abe4db581c636574a65175930b3e8e64271f7df527804a2d2d09d6b096a27f	7411
720	d1368cd4212452edc21471e7ef06e4c51f49004af76a5a748f9c8f954a2c2a9f	7412
721	c6131c370f5cd624488ced10fa8799e6ffa1b179d0e8bb11c8d7d4ed4369fdb8	7431
722	cd3800c2efa2b97bd1afa6e6838b0351b1660e49582d9d0411e53320577fe79e	7435
723	bf9730b5f18515e9f33ffa6853760220acfa90006c55e25fb4a814d973f2101a	7438
724	63539309a3744efaa91d4053c1ca1e408950983d66cf46cb5c46237f8d4a6a78	7448
725	a2eb1d35ecc4259b7620d5424d5ea6fa6b077ce5b3c3e0b7f29ba1302f107cac	7452
726	1c27e4ed699426ec659731f32c80077c4822b0ea3dd4a9d47211ffb5979ae2d5	7458
727	01785559b770fdadd6cdc0ae4177793df658534a2284f483fdadf14e55ad97ee	7473
728	cbb6ac15818d328046e5dbb87347e9a96e78f134fefef6bf66ec000a30836c8c	7487
729	71fdb411f0577c8c5a727a242831ffab74ab373eba2de265b1cb8741d46be76f	7489
730	b7df9e19e36b87195c93346280d07d5854073892ae35bef1ea29b06ac5874236	7493
731	07729d3e494e619f4acce450ad73215642e2342056b9c0411e25d3cb4651f182	7514
732	1e9267ad6b99a284a152f1e2c019d0337029d3d740e4fa500a3c5fb9ad72fbf9	7523
733	093bb7a7f4094cd615ebe6733fad1e40b8fb6a36476379bf7ed25efa537a5d4c	7526
734	7820e8a8c78ea73a9f537dc79c306754ef60e6ae582248ec0f319c0797f17a4d	7539
735	d7c07df83524118dfac00158136fb5e22b8e223fcebd33ee29ec541b5a49edcb	7543
736	93bd9b39d4db946a52a26d0ffea5d1c743737a70bfe330ee2fcdf8fa94cf9a9a	7548
737	ad967365c3d20f872a477c36cb52cd7eb6f2d4614e0fb7a75a4c52f41cca88f6	7552
738	da9fe714b7dcd2e3664b38180efde6a7426362219d314742b5c83cde19f225dc	7567
739	b834facb213669fd281cc62fcff9d797d639eb40d47fe091acba78ffa3a292ff	7574
740	21b37cf79d8a880527eb1cb5673f164a5623f605489c2ece454d84f82c1c6373	7579
741	ff7ab8d3f679bfc07fbf9059582aa83c733a71ceb696f54da3aefb7b39fa5475	7582
742	30d65dc477d03f7809b8e07c0bf95b4a96dac0255cd85547a493bc705169ed88	7590
743	635062f7f7f408ce7b90bf8c5b62d00c729cf4e7d756f01c421a744c5d39de2a	7595
744	7116ff3ca72642cb961ee8e0b9f00e7a24ea22e4a6c2335fc16b8f595c60b7d1	7618
745	14ae299354b002b57da483d4b404b5f080d6276710aa044ca5ee5a8a760673b6	7624
746	e9ced57c6c5f0718925f22422ba1e4bfc17531875c689ef622ee08c0dbdc5b85	7632
747	6c2c4927e214772a3acfff4832d9ef437423926fc1af5848b2a61b3b6d83c3d3	7634
748	e3fc9bda080b01f5146f63b089bd6b11940b2c092c832cb0c86731fbe3e3681c	7638
749	7d319d4623e3ed057b5d15dcce8554d20719e53f05606de647e15fb7fb125f22	7667
750	577d63ba8168247a22f89fb0f216a487a049ea231d5f2725e864a75ef363433e	7670
751	ba1d17b6c20c318b09a0c44e8b307920257931c9c434621bcd8879816db77f8a	7682
752	f943cbdff65abb2ddb7c9fd76cd07b544e86c7b3e109dcadb7c20bf0fd0850b2	7699
753	c299a4075710ce848772a3e827c6b8459d996e1fcb1eedce68d6ec7f2d2671a8	7704
754	4f81cd9ba455b1e6efc210dbc55b615d874fcf8ce7e514446ac763b25d4dbbd2	7709
755	3f66b33523315564ecde438b798f45331c1adca07b058dc81479c737814b9409	7714
756	f1d334c9f603d59011b0ad916f045e00bf47dee9e889e39c7841034608b6ed34	7727
757	836f0c4ffa0d5bfb2d938d93858cbc6b60b670befa87353d438b7867510ea992	7745
758	3d49219c17aa866f5eea33d9654807ce45842e6ac3266d3d5c9787fbd89173c3	7749
759	c9ec3b5deb78f6702b34bbedad3cc66853a71d8af7562b5d58f095e0ba15721c	7759
760	a2b630e9a744da69076e99d5579391418a3eb3d38fd6277f0b94d53bedfcceb0	7760
761	84edec94cbb4214e5c9a5f7c05b269f8fcbd5c026ba50bc0ba1c76023de267ea	7774
762	77ca08067c066c6d0b7c13c964dc33eafc26438496c631808834ab320db6064a	7782
763	9f18441c387eaf297cc7155cfdb0f8642d4aa42b9b0c724075906b9f3a9abbf4	7785
764	66003a122d1e0f31bcfb18a7ca58e6b72bd9824cbdba986053c7ed6177a64aec	7806
765	d716fcecaae80fc2f61b3d88123a8c7cd1b3525280b6a7ae2e36a802b1ca6765	7814
766	43f5903944ecfac59890594b70f6f90577726cb826f6809c606f4ea5459ae499	7815
767	532a6d2f88bc336ce4362a590462c90bdce37653ea87bf3921165bfad25e51f0	7819
768	a05c48fb13a79610f8ce63a91f5487ee9a54b38075f4c5b9c554198a268602b7	7823
769	e8fc02e1bb7c0484b7f39921a777c700a3bdd2cb35acad6ee9c39ef93077c8a3	7827
770	da9137f35c617b99109f1abb9340d7142a72cb1a745e4f134f577647920ba689	7832
771	613cae158d9fc86f4468b1a9a756c4288cce78c692c3115a6284fc55ac9b74dd	7841
772	ea3fd7b50aa3255ff11c6234f0dd1dc47ba1f329353c7354deeda09de64b9a0f	7843
773	c99dbe298a01cbf82466254379c35e9f5725c8f003074460c736b7460566876c	7846
774	3b91ad9415287dab9a33b72f23998160a3d992c4bb5c62d10b1e128b3cc154b8	7857
775	c8faea862610624ca7f75ee23f0db57c5334fd39f0aab2637156c64c9cc8e085	7858
776	08e777faeafd9bbbe2c4b8e0b7bb119d89a32b8b0f6e66b64700d71e1d61624d	7866
777	9b83c4c253ff9cfe843880b50b4284c702e4121175ea7c56aeac897b183512b2	7869
778	c7cba619ec7208eab3b42d383650fe2c2574db6bad8df64af47c5c11745983ea	7877
779	3463afa93c72783a78a8d33c35615b8545380272fe3a29ffdef6460c92de2f42	7879
780	9fffa9decefad912291741c67e793c68bb630ef1ce46801b2eee8fa4d746a910	7884
781	189cc8256be228e6015a87151e266c5da219d41d02af93bc88a3748415493b39	7892
782	89fd1258050b954bfb5c52485c8a41cbe2e7e9498f438029f20fe5a5a275107e	7925
783	e3ac27f5bf98d34e131dfa952a6cbe0bdc088c5504022e42bc411b5d02c1f692	7941
784	2e02f20e1033286afeb6b81aad7a6a2a32b8fede163e6987bd02185ca47d3046	7953
785	de7fa05d66a039b1ef317735356c6ce0b1ead97e03b4e065e644edf1568bb499	7960
786	160167201e01f94723be145e49ec453147345fd842f90fd22bb0b9b6b2834367	7970
787	ef025a2acc85ae47f39d9a1fbddf9c9eaf084ee3b47a42ad537ea10ef37cd0e4	7985
788	c49bdb5e13a94bc80409fb192773cab8e248302cf9cbbbcd5a05bc8f52656025	7990
789	246977acddbaf2d2efdca14ecb24b7e9d43e2ccd5963234035614dc37ab3eb4a	8013
790	98bb9e29556b45ac58ec4bb94bf4e374b4b145927e5b0ad4a7c7ed3b53e01f76	8015
791	25103d603ea772beeae96c5f566ef4d36f7862203942a6f6f9e8aef27ac14a41	8022
792	38fe5add90123914d627ddb73265aedfed6c8d165eb92ec2f52bad30af61c753	8028
793	be21f304870962ec83605445b86a13d1e0df98f9140e500ef84a0c779b63a17f	8030
794	48c86cc209ce9b41d13853d6f1ed6e62fe6f6a43f0f3646431d448dec1ad89ba	8055
795	ea1a378c30b9abc17d938745d9473ac3b150e8e3de3d66e9c51d7a8871aeb057	8064
796	353d043aeca4e088d992449ce109e97a88ef69b96d7736f8e2c0455b5559994b	8065
797	9496dd2d0b69103141b8a0aee6ea1c2fe7e329049ac55bc78df193339b5b7041	8078
798	c584ef45d900602770083e5a1f965dd5e5c0fb510a1d75ac0535316a1667696c	8087
799	eff7e10510fca2da8745a3995a722dcf9305322acd89bb1789751420adb20ee3	8095
800	c4fec46cadd6ce2c2067be50093c7f9ba73d9ef85d7da769f8ffbb48dcd4be31	8100
801	d0eebd05faf37a9f38475eb3ee221e79e1601f08edc07be7a89f13dcbed3ef24	8101
802	ebcfe4546b868be871a5095eb7e57553b1c7645a6edbce0433ea762a1f433ddc	8102
803	65ab8136cd01494e51536bb0a8e908e65ce327e5494ac16546837cee4bfd69bf	8116
804	daca15962b27bde8a9eb1fe653c4b730713c3b57cbfd610dc68f14e1b1aa3d40	8130
805	07f60ab23bdf5b63bdf7300b710967f7f4d143a631d21b6c63af3ccd8a2c1439	8131
806	acea292899631017d42581e04b95aeb02e8533245ab891ba785d1c799a23af35	8137
807	d46c15a73193b295902b699edee36a7b36f3dc1daf5b7799c0771ad13af919ab	8138
808	f8f1ab7c3c74956bdd9889fd032e149e777ef10dab6833af58b79931f0ec0bb8	8153
809	3cd404f21dcaf897450159cb6bcc186c0bd2e1407f6236f2b920798e4d9b6611	8158
810	23c404ff321235a525e3a9e58f6504b4cba95a5b7a68740cf94513e367797b0d	8178
811	e8014815ccbea83ec2dab9a3f101ab2561c65e71ad6eca8e2ed5be10899e8a59	8183
812	ccc0fc87052a0a7fd7a4acb234fdc84a9e630856fec0db356643fe82866e6762	8186
813	e7fd276244c88585837f0903197c02cf5805ccf87819d7061a3f74a3d5211944	8188
814	81704f07415124f2f5ab85ce1ba09a7a6605d990e3a1da9daab931ec31c6fe93	8193
815	c58e8dd276881b638dac1656aba6a5fbc5b462b56a259dc0c1701b92cf8a7a43	8203
816	b46545e385cfe8159ca3f2d1340ef9654f7aecd3b6c53b5364c109ad2648d6dc	8216
817	f4c995888f3439537a054a2921590e0fcb6d7db6b14c019ffde6433850e1b0a1	8227
818	f31e4e5a8679b95608ae9f1edfda3ec28b1929d5f32b411b1202ac64b1c5ea65	8230
819	f13bfea2042c959683b0fe037212c708ae9756f62d80224361e7685283e8ade7	8238
820	d40419b7f68d34049960303d9a38600ce6b9ec92e8b9c9f3280bd02b5da9404e	8249
821	1ea9e71b45386c261e75364dc7d526d5cb8b8d9e68c7254c7882fbe7c5d17b06	8261
822	825af509d9a5e015ef5fe43758e9ee8dd987a165674956ac694ac8b0ab3ba22f	8262
823	307321f9a6ce46abd68c417cafab251027b81cdac6161c1d8b524b498eae59af	8266
824	dc78e9a7213fe639fe4454cf71d6a00ebb7e59073746ea4a93f0063c34761b32	8304
825	e49c8d44034569060093189421815db45d77dd159ce8bf5ec7c9b0e28dee7d74	8314
826	cc49d57279df8a7679583a16140b985ef83e7ffea4f7a55608663687df12720a	8317
827	05b4faff2f206c1007b4635ee951855e278fce7774896877f500876b8703984f	8333
828	5d66c4e6ef059b10219cd47559cf5d4b7678ccc8957753c00b51ff3f1d9cc030	8361
829	257ba1b926e99e4ef8bebdc0df6b6f0b1b766218b559ea0a54308ea34fd13903	8364
830	8845972e1e0d9e8d06925e07b269d432ad7bffddb4d4c338e540fd8aa792ab55	8369
831	aff572f25cca545d9d77e236a36783c7718dd8d0ee02be94e9bcfd3d1b85c458	8385
832	d2476fdcdf8775965200fe0bde9ab86a2c1a6932269aec836d48a257cfbf799c	8387
833	d281255b21e5c50cfe62f731c83b88ca2432070af40e3eda07bde61ad12f5f1c	8399
834	f77dfcd01b3353680c2f0ec9e62bcb3deef69415fb526065c779392b865f5e56	8400
835	1de8b88703b4d49ce719511a882855c28be06a5f52c7099cb2d317d880ebc859	8403
836	1978ab75478de483f126f1854e5c43e07762597fe54648cf43e67ffa69b9f66d	8465
837	d9597b89b3a26c01cd388ddf9649787860b588d5916e5a1bf303eb87c468f354	8482
838	c1151d21b53f0c05a462da12d77ffc298391aa2c30f880c7aa19c0074b53f55d	8490
839	45b92c8fc50d3c870960cf06cb474255b5bfd2a680c0d2940e7f59f8cc9703dc	8507
840	88566eb9765229e244dab5e9d820f40ba5c35ed6d0faa17645bfdba110657ec0	8516
841	cb988fdcb2afb96fae8cac370f563e4586f03d3cc37a4db9d4144e169c162108	8532
842	15b7ce1cfb8874c3f01cc2e4f2219755ae1455dbeb6abe528f2e90354b959f6a	8534
843	d235988ddcd235945d11aad7661a3556ecdb0c938994c6310e4a9eb2867714a4	8535
844	4e6d203129f4e28b4ab9ae5f3ad24442c5910dafaeaf6207aa00a91676ecc5da	8538
845	b39e20bab84eb40b65e7fa06d4e2892388a3b232eb5852fa832d9785b4478044	8544
846	e884eccabb7c3dd891e221028c71ef09886e9c77a4b2baef19b33a9189a84a8b	8547
847	38293a50848aaf39b62af16c4061b30b29c580d2d9174cf4b0b5cf6ccef18c48	8550
848	74754a7f47e1c011c144ac183ee067821438b7805d3d110656af961c19f69553	8563
849	d900c62a82235e5a56c2cc345d537831e7b804fdc2dddb4d54b833a164b74335	8587
850	735da0216e8f912f25b600783afdcf93efd5767969f02497f8163581e4274434	8597
851	3453cc846bec15f927c074118c44d5b659d442e721d81772e207c2f89bba1c7f	8604
852	ac58b8d5318206f5d6661575ea1c0af9053ad2fecf036074a088c2263cd967b1	8607
853	7fc7197f1c46639b61136ae7b65af60cc00fe3bf927efd877a3fe823ec30af76	8614
854	663de09bd95e875534c1aec46b25f4981994b16feccf23d33f1b1f891646d947	8632
855	4852029e9148906fb847f013a0f26707b8bf68b9222498521845160d9d6a596c	8634
856	a66f3f0d7af07cbaf7a693641c4710b8d71850c01707b67186d26c9b0634d3e7	8648
857	1d986ba48ba178b6b38ed140d259fd238314e1c8c06072671080256171f874a7	8650
858	4905a983456db1edc111a10dc5937a2fa739068c0f447d894139fa1c7fad97f9	8651
859	017723fa1e2626b50c7f7e8bd304d2ebeb515f143365a7be060d19c8104222c4	8654
860	9408ab38d100df8cded61c8d8af29d3fe582de6e65fa85cf02cc5bcd4af567e0	8656
861	cb2e2693751f39545fdc2c130f298f3dbf03dfba85f5e74fd43342f460930f1d	8666
862	19daaf2d473f1c2cc4f1b5ec72d2e3c4ac3b140114bcbf5ee26ae2072d0d044b	8683
863	b544e5143d7789728742198f5e4b7f93a6997b9ef72a23915a666f1a96ba36d8	8703
864	69bee62083754f5defb674e603a7bb8610ce33958bbb6fbf6473c6df8cae64d7	8704
865	e262dccc84aba4d5ecd197c4cfd8724ef7f4b67c632972776211282aaadc4adc	8707
866	aa594a387df4a7598c3fa938a1c3a0a820b3ea55eff9f3dd66fb7bcdf7d9e2fd	8728
867	f37f9f98394d88bb5e96190f100eab8791683a064df3bb2ff391299729502d14	8733
868	f64df5634937af9aa84dd0408a1b82ec0907a15cbf6cb2fc3ecbd7936b4a8cc9	8765
869	4edb841371418ab63ae81444d1176971cbf2ff015fe213160ac62467b21a4353	8768
870	74ee36dda3b0ccef6c921f347c02b07d21b0b2eb2953604df49a0bfdd3053a1f	8782
871	9c427d8aa2f750a1d2e9630719b422152621f3cbb3b9ee70465e84138b1d27dd	8791
872	e3ae8cb180a82509252867779f1d8b944c21ecfc81970c167a40432687a28ac9	8797
873	ad47830331515e00e4c58395226a35331127635fba56c2eae2dc75f68d226604	8807
874	4e05d9f80ca7efebb75e603115583bf380d29234b7ad9564ef2a31783622ddfa	8816
875	b30446dd45d047d77e566cd412bfd18847f9705d9e9cbc7c6196aa996039a928	8825
876	ad5afd5e1786652fc302ed4c6d227239502bf7843eb86ea79f7e3d7673c9b93c	8832
877	5af82ff8e3ab73d5054e22a4ef5593b21ac6c3ece7eb671b3d54f2863d601683	8854
878	3e51ed3e65ba36afc7cd53e952675f7addbc62a974e9f3066b7b6c5e2214568f	8856
879	b9bb1e015299e91fc7f75a23ffd7dba1469b8ed3b3aac4f446a568f3390ff9fa	8870
880	06b64a794f895d4992c35e1468e054061e850ab6b3739bd5f473b1781c53745f	8877
881	a66c614e49cffbc4393000c76d0bfe1ed0185742aeebb4feff5d761bcde4bd81	8889
882	8d378af20995dd95dc83586d443a568bbba6e4a29e23bef1c1ccbbd17bfc1b10	8899
883	54dc83717db080225e97385341f8de376fd3c0c188dcf897f467a7f3c86696a1	8913
884	0ce67bd7da47b88311bbc0c0f2ec2dbcbcda843324b8e8d2760a05024fa997b8	8920
885	840627d46d1f8ed2950a3d200848b56db704ef3417645be190cf669f96c33e44	8924
886	9a9efbae35a0eee20894453505798118ed8cc1f59a47161f59a2fb0378716d30	8926
887	addee7ef582793265769f52533d19781529229a1799db7772216006f183e1d60	8931
888	49db40f84a48218ec7df01402ce12aee5512b63020f88ec655af24ea694ce67e	8938
889	e68eb46402aab99325f0187b06a641e4d8ecc7a5c6384e31a2e8912ba0f4e799	8940
890	e76eb7b13d40d1fa861cba20be605046d28d98df8ffb8124ba52090a48d267cb	8944
891	c3154ffda8322f7c2f18595dbeb4b6d166af6a9de95e338c9d3dd4e2e4fa1f24	8945
892	7abcc6e916bcd12c270ab213c161ed759d419fdc1a695323f1275c603f2f1b62	8948
893	86c155f1d026eb04f2427cf0f93d8d93deed3d20b7aaee2b1322853774a788ff	8974
894	0f1de5030276f0a52194e7f41ec67b4ea37056dce472522996f6cabc87b459c7	9002
895	6c11a11bf80aa4447ad1155426315b7e87f9da3f8db88daed5818af72d12d108	9009
896	afdf6244aa8b2ea56ef5b25afee2015f1583011dfa8d991db3fbe03304adf21d	9019
897	4500155b4d54039509b7127dfef2d9a7ad2a334528c9851d5c53a7b1751e479a	9034
898	028234ee4317f5e9a31de8de5fd5388ec055db62f872ae2d40a2700b90008c32	9056
899	b4c900e94efe1a5c904086916d809746b0e87a00e40010ce964da3fd59258aa6	9060
900	377e30e278a37fc26b9d9875764be3d7f1e2c180ff55594a3c3a912f9211cbc1	9061
901	c78135d8ac9a1d15dc673d53ce8c556a34f286c26b38f3f76466d52be6235706	9064
902	e442ccf018ce95e527ab824be5d1035c5c01f52ddc5e57a51e5c28040082e2fb	9077
903	b0e8e8326cc644c43a25dca059390771e507ce28ea1b883565ec1399614c1d8b	9094
904	342bcd6f29778fc20b52b67835631c131e3d2c95ea61b4918b89be9445716ab0	9115
905	96337d1682a8b5fc697c1f118525a3b15e8b4fc8d685772708780c377b5bcd4d	9119
906	c813c4e54a831c8705f072e528a03c97e14f70286c76e8e86436f1d710c52721	9124
907	9d5d94b25b251adea8a7ed81f9d154706fd87d6e1345aa7e8e527326a2daebec	9152
908	36a7b5182c6f23869b6a22b5807a14acdff1bd7f18c319d7f0210b083c85302f	9155
909	6715ddc7304e0f9010abb7d965507129a98c09924a37487b4459f8f1008bb019	9160
910	a4b4c51a754f7c7f58adec93af17e00f124aa68c69a7594bcf93905f571a5bfb	9162
911	b06fab0dcd0df728ffb57b3ad07fffccd533b57597c6de94f817f802735ecbee	9164
912	e3bc7f896e4b3cd9b49c1e36dc3d5f95171bf47a282b5edf0e3f8e252f8b399d	9175
913	fcd90a6c375a00db2a35964f78ea8372cf2b385d4ad9422cfe7b760f03b53a6b	9203
914	b92e8864c01af038028d6f91967ca787bd3993f36fc02d61f0cca006ab53da78	9204
915	f767ef90cfced275bc61443c5014201c35390528a03f1d274210f095cf908149	9218
916	f6b48e8f15e3e04a7916b548df062fc66bf44fd17de7423bb72fbbf903f1bc81	9229
917	ca6595f6e6b58b27d4e2970af33c2cd668e578330b0459162449a069fbb5d566	9230
918	27d3831ebfa14d6465bcf13eb06a353809818618f802912ad26d98cd7c9cd6f2	9236
919	fcbafa27cb2a80876c35a31d092a3dc303ad9f8d0397ddac575bc3c9975b39a2	9237
920	d4af8330ef9f43f889fef0afe3c388d8e87a097acca2bca4153e55dadec02a77	9241
921	a03666c5f2a4e1013be77add3e1daf984af7e7a7ae803f8192ca8476c1f0fc38	9281
922	575f3426bcc0a1d7d9a5d1946b1a8f330f9d731ac117744cbcef46d4da046454	9282
923	45fb36c5734e20a2d1e6a85eb4750658f62c5859506eac0d633ed1d6f632656b	9283
924	edf5ea5791c84e7c7459f9980c84922effbe5a15fd3ebc4b300b23e519e3aeca	9289
925	17d97eb7fc36a0da8e8a0af2eba9e3409cf70321a309063db55abd2677c09b38	9292
926	738d8528a17fd305860ad1e4d4783bb28fc6616474507357fe95e33c608242bd	9335
927	508f59c857a9c28d68de088631ce4143d384c606e41fae74aa32e44d6a8c2648	9344
928	04563bd96656310e67895cdd0c5259eb1660127aadc781bb49020c94713c7608	9354
929	ce4199d168fa01f7a4e3c24187670efc32395bbadc8458498c34b0d23b04720b	9366
930	ec9e8886e2c6f7af88b9c0fbe9af4e15dd87ccc5b710b85fcd8abb98536f7588	9370
931	5cdb7405c74e9c53cf0d905ea5b30b6a3c4cc62abbf71bd894be332a13934f62	9377
932	e6163a27cec82524d9ccd71a179065fe0ae7f7ee5dab79c4b502029b80dc728f	9398
933	ea89f4e38732e8d4ad63eb354dfd28e8b2093dcb2d5a9884ff81655e5c260d14	9414
934	eb3928750e2bb899c039996a00dc577d3107e82eb9f2f5ffb1c220601f15d50d	9422
935	dcfa35e70c6e71b734c7ef1b5c387908af4b827393540b186d0b1953a8131724	9429
936	ff3f33a3dfaf58779f04f89f6a5b0f53821a6d57c5de5992b60f63435ed61e8c	9444
937	adb47de6ce75ed9c8d0feade1eaee0f133484f0f15d27388dacbc5b40bdbfaee	9472
938	6d2d203b887b0e21bced3dc52de0709791e568cb74c2e56444e71ad8dcb9864b	9474
939	c1f1045a05225538d1c4b6c43dcd1ee1a8c09954776ef8a6a639114d97825bab	9490
940	af8285eae9c949174969154d872c50af496669a0c746efad44372fe026fb7cd1	9499
941	d6ed937915c3a8058c27c68db521d843a07a1fba20ea91cfd0c56523e307083c	9502
942	c73633d577fd177ddaac3011b6a42e140a89af1abc48bc42ff5d25790b45dc25	9510
943	4e9a33e4789f0787293e5549114fc458868bd3e5b71940d2389883eaed5d1fc6	9516
944	3a62867a4ea24843a9940424e72946dd3095060ca4f7203493a01dc7d04982df	9518
945	c955fea8377ea74777e3a74bf56e37f60a6b413fe1508602c23aaf35ce42cc67	9524
946	9d25e0db7e6f361ff56c77c54094f5cb0f1efe30a86d002dd245646e02415591	9531
947	fb25bf8c4c9e56e7eb5f825c14fb7be251b06fd7c9a75add94cca7cc8252bda5	9533
948	80eb16f30c9876d03e02f1dc4be3e356887a33fc5481c14c1334f0a82586745b	9555
949	c7849a73aee8fe7b665efc10a7ffb5f74878f83cacc0cbd0267af1b640cd61cb	9564
950	35b9cd9c0f954635cd811daab5d2889b552287f13282f061384b8063a6931484	9587
951	99f93187a2550be2a954200e811d0130bad81540fde80c63ffe6645ecfacde95	9598
952	b1124355cb5dcf53965944ee4aeacb11e89f8b9a092a96033fbb99f85b269071	9602
953	21d9152781403fe43c719b22c9fb8ab857c1bf2d3751c310fd91f9687f21ab42	9608
954	80b124b07cda162343920e18708d2997b5ab66249a95f8e28fac4ce23412b51a	9614
955	5424174465e977f81f9e5120b92a519ef37cfb536f60a14eac87a2d47122d79e	9632
956	00222fb227a0668b263208e19e287882427b2ddba6e2d126d31cee22aeba5adc	9636
957	fcaf697114f4a863002b6cb01ab40d56f1f1250708c0eef0d19b74addb1102d0	9637
958	2ee7f6f3c069bd6a596ab274da1751ca7b7dc76c226eafc3a6cb93e59ed7e35f	9641
959	7a9905b1a45e85e5a34d8d47df67e735fb28f348f4e27c4682dccf1cd064f7b6	9664
960	bee438a2a50e44775275a3623c19bb895c9d923e0acc82a31647483f0c2aa27b	9665
961	fbe9ccc0ae6704a937121d9f0b9f3a5cdfcc18049ede06ec8990b1350d9cb4aa	9673
962	e81fd88ebb57192f13c828c1a28cb08c0c8885c0a79e93ae25987b3b63f6d688	9682
963	d1586083c34253f655ddd6692399f2b86f1ee0a64cf57f6fc67fa89b0ff3937a	9726
964	1db56f3a72a96385a33efd41cacec6366b580f3d8460c4d25f01d494776d3283	9732
965	543052c1c57b406d8106bbc96ea61aced2ca58e8a17e1d0a1f764ff5ec5f5bd3	9769
966	74946d120ed46283ed3237e6715978c319d078066b2bf976170b85656e792c82	9774
967	5235694171ba6fb6f4439ff02454dba1b60d45b9f81c88558dbf6b985d2a4609	9775
968	3067921e888c99225ee3c33dc8d5eb58d3b54eb60cd88c5bb78deba9b536cb70	9784
969	9e1812fc27e96938407caba1f743098fda64f78c50ce93544a8a7224c3566485	9796
970	3bc617a62c4dbaa9b0845065c04f1e63c4d8f2b64019e9e832513b847486e43c	9809
971	a757c13ecc2049b7cb6547440ec9bcb49fadec8ac659bfd5c181e6a3212748f7	9814
972	34779be68265343a2d094000a643230f71ef380832b724a724e28f7c94d114f3	9832
973	9d402b5cf279e29517b39cde091400d7b198bef6224105cc5d93e0c39ca964b9	9854
974	667e1bf24bf5baae858e50756250fa1317bb5bdc9b31391bfd097695e414c7d5	9855
975	79fafa418422ab67cfb4e5fbd35dcdf0991bdef27cb8746e7c2b1c9fd948b853	9874
976	f4f178c9f83b404e8f7583e6fdcf2857416d6fc65d0916cdf22a94cd78ea2e1b	9885
977	31fd313ac6a59ea16355bb215038b31bfad34b9d3efbceb9dd661d98e3adddf7	9903
978	29b469f6f69a9764e9e5a48f94811292a8bccea6d03ba3344aa393d71c00818a	9915
979	530b32ef6499060eebe2c82acae31d6576cc8927547f6f0ce1f0154bde914a0c	9917
980	3105555e77a1f92e2938bbc9d758f48dc23a96f2ad7b43287cacab7e229917d4	9925
981	9dedf4bdb1f7facfd81c6d4f24ae1f8e1075b7cf724b028aad6dee85a03ab339	9932
982	71e9e02cc2dfae72e14523936d4313c6cb1002210fdd319e849a62379bdeb82a	9938
983	4d23a070243541023d91aaa60f09e0529fc42520f1e3a026998780547a01b246	9945
984	f2a28ed00e5a15304cb1bd2ab1860f80682e92d8fcae83fd2fc1e7c867886830	9950
985	883ed3963169bf8b2ae65589af0fa6263ba70dae4e2a1f43fed744047b3c54c6	9951
986	f930d46de2df4897d3d63cd72c26f622a043e04140e2576f713c54de539d1d27	9955
987	f41c1707fba62c5e4b771b1109585503e58d7cf1fab64ab151e778a76f50e61b	9956
988	2c11a9b93a357e76582803da0e2f64da6a269910ed58794c042ea6ac52915910	9958
989	f487c17d2e651d9a0ec7d93f182c574c67a22f24ef129396587a8e053b565962	9959
990	e6671cc373ba7845ba4aa76470ef7a1c93d74dbc94519891017778d754fe82a2	9971
991	67f5ed795332d907b05124c39daf098904b20f4467fd997f99241daa1aa17597	9972
992	d3cf6dfe5c0f5aff2089394ab2f18391f5acd5ab940e1e73360c3e65106e4693	9987
993	45421e0aa1bfebf59abee5b2c0c6f654253988b0b4bb79fdf2d42386ef9f2a6b	9989
994	a2d9d5ad06d6d58b28fdd21c037d1dd543adf64e0f5504a438861a75baf93c49	10001
995	d26ec8ed0e8b0856b46ad4054a46811ff0d1e2939cb29c9656d2a832d56330b6	10022
996	f2f148e68fa670bd1ab5ba833fec20de7873c1808e7ac7a12ed8d3c1a85f4aa8	10034
997	94bb7d6691c9b5a51e96df35691639c8afbe70f2f4d5f5c26b5526a7ebea362b	10046
998	f7d5e34fbdd347c81700222e4831d14d81c5bf73ebb80b7c1f0a35f8777e22e9	10062
999	d79cecba2aa6526725767a2cdce15281f55623cd2c803e97ce6cd4207a2faeca	10063
1000	98d2a313ac2d98485e8998d56c9094ffcbcce7a824ab38dedb8411c2ef46c650	10066
1001	8796bd16f91b2f579a36728914235d235f92e7a6d87c75fc81a58a87af664cc7	10071
1002	996b6cba56409768997d646e6cff6872179a5c9fd653fd88cdc01f2c87db5715	10073
1003	abd24f8c73c4ad7b6b29e5324cd07b5b06381420232567499238ad3ab2a6b48b	10076
1004	7a10dfc4a1ba805706a26ebae68cbd3af5533ab761309845a60c5ec29e35d7cb	10081
1005	8f5f6eb4c24553caae827987c253ea97db9a9242e62701a1b6e5a8b99b6cbafa	10094
1006	203a7a12718afde531e281a771dea49fd3b3f9603d58819a03f09cf80211029b	10098
1007	740b7fa492c626a351a7d6958bc2a7283af43382766c2e48858e96bbcec8c8f2	10105
1008	efecfdd7b4b65f9fae95b7d20618879599eca9dbd447a5ba40dd0458553745ff	10111
1009	32a4ef819232b57b97ed81ca114dbe8d652c14b1b7d405d0f5e76f2b814e1bbe	10116
1010	cb874f4fd21adf6d453202872862901c82b64ea12b2fc42473d60767d54ec0c0	10118
1011	d87bd713bbf6ac1057f0a478e3b0355a33a0b138091d43ead70bf146d4110514	10122
1012	bd2b12fcb81e59ac969002e58e14e876e6e10b8353d5f48ea0f65cb9ce201b88	10125
1013	502a72fbf26d3a6bd882957de7af35f0635ce226c3518fc4fb25e9846b818231	10127
1014	1f7973fb4b60daf5c1d91ee37c3de7ab29488aa5c0a393f1ba1aa1edadf088cd	10160
1015	c624299fb7d31ec22c87778e0ee185677f67b0f3004db68b50b4e8517528fba7	10162
1016	377e30d84dcfadf244cc6ba3c1f28fa4a88b1bdfa95e35ffc3787a190d6da805	10163
1017	e6fac20e618e41b73cd7848a75307f93b8debea7259cac7047fb0539322dbba0	10168
1018	68fd833b6e5a51659aad15a0efca139828af010e0cad9f45984c04e61e3dc4c9	10173
1019	21c416bd6b420000ad4f912c1ff2a600d876efcd1e8b3faa05aa45d21521fcda	10179
1020	f48c7a65cbec6ae0ff2a6046972b78fff48459ea9e472a28abd1192cd4225264	10181
1021	7d55e59f95ae67c9634e003af01c80f786f549ec658b3a7cb39b63010ab38451	10182
1022	bb0224a0add2414bc5da3a705b505ac94ceaec33224e97ed0c08fa58bc3c240a	10195
1023	e02116f38508a70b2dbc16694ada08408bb100bd6d94b676aac802ce78816d87	10200
1024	bd0bd581f88ec08f798c9082117b8333ffefe35b8e534cc462de89b20b516600	10205
1025	509f9bb3db615b6ace8e16fa47622dd2431838332b728c236ae46375fa891172	10208
1026	2e06a3e399cc449768e5d9fc5a4f0ca081b23b0d11d83d7dc63cbc8d4d1b71e2	10230
1027	816aad630fc240b05f44f57b63059652a5848f4ef412c934f3b378a53f36b5e0	10231
1028	58cfddb10bd42662e9daf56eb53fd4945295dd9cf3ebd2b10f5e4d048353597b	10243
1029	36a062607521e750c810edc0f745e7ad8d2c379f0ac1189806c3f53079fcaf0b	10244
1030	bcfa7bf0959baababc3519c0442d3d51f41b41fc3b05f9c0e240163c2f97a38b	10254
1031	4aefdcb09f991b7e98596bc07b392876cd4c1a5ccd5327b8113a183efdb01f88	10260
1032	750f0794e0894564e7f355097e2f9a50b8a0822c7402f6e25ec095d1833ebc76	10276
1033	c7c50f7978c2f0f0d6d3ba81e1911932889e1d4c37b38c82d7b2d729278e789d	10289
1034	677458b286009e6dbafb470a2e61cadc76cb34d7522e9efbb7c0745a668996d2	10290
1035	a5d4ede83759b1e209028657bdbe21091267600d8e4aace193939515363ec90b	10302
1036	946c15f9fc1b2383a1e95565a120dc95599c4682b902554c175befac3748cc12	10307
1037	29c434f51ef171747ef06a9f8d68b71a8fe46f70ce7937b1e419369d1ff7cfe1	10332
1038	63d99232d13e2d47227f219a48d79d97139f120dec46f46c99a8cddf16d5e365	10339
1039	1abc16c7c9a7a9c9dec394db9c8f3d0ac1072a8931c120f6472ae886fe8b21c9	10342
1040	109cd6a5982c5212a7f7414e7f877278222f06327de51a90d0144baacfcd1f8d	10350
1041	df56f6089bbecbc07474b9c81ee0d0c9868c63d6c2b2d4832185f713b6aa1162	10355
1042	6309e6d1af1533a042c5051eb2bcb2efb7bd427440e05cee359f48240514b3fb	10369
1043	12e63fdb6fd9774a8baab3714043f7b667260280379ba57dd9d6a1d00fe66ee8	10399
1044	2d3da1c816e44bc296b5b90bcd2fc371658625d30fed61e788f33acea6549c3c	10402
1045	149528194963eb224a5c6950a38a3597c819d365f28bfa2536553ead11171bd4	10409
1046	19e3b1dba60989ba5dfe1badde03bdccf48ba3a748def839c684e6ed401f8b84	10416
1047	ee1fee8eca87ea5f7494d662b2a85ea63dd3ecd22b57b6e6165299a695b806a5	10421
1048	db5b5d6aebf6a413dc4d3ed0be057c41ce2376e35eb1bd7d4013603699632577	10454
1049	63bb40c984afc56367d511f695167841b132a41db44a1cebf6ebcab4c48dbac3	10459
1050	d0529c3fb47ad8d94de4a11ee349b4581723434dd312e998bcf1464cdb3447cc	10473
1051	6240bbc1e5c3dc60dc6046c3ed6bab6294e149a68fcedce41704f5a773dd014f	10474
1052	552ab55a1d9bc029291a11e176a528c6b236eb0b94ce746a976f629f70ba6441	10484
1053	320f50c4224315e36bfdf7205eb023943044fcbdef2d5cb61b451ed2030d9e49	10489
1054	cd7661e826bcd8aeacf062326f688f420f0df2da4ae5a87e8292f1a22fe01f7f	10499
1055	aa0fe4ba1242df172a3954f73a0a01c6d0cc4a821b8eb27d573251b6fe0eadfb	10502
1056	112156e931c0443d23903ee807c1d2a86945a71761732ab4e2a0d7c0708084d4	10504
1057	1dd9a7cde327253a172031d6fe777ec394c6c67dc81e807b719ab232ad464118	10521
1058	9514e91ae1878f29f80b5e0c1bc021d36636f37dd8f8ea4677387f59afd14a11	10522
1059	f78252d235d0a02a92db8ad2b803d09c71e1cee60b652d49ff246b1035bdfb74	10542
1060	ceef373c22be0379cb8866fcc09e66fde9f089439347402e935ad9b1fa11dc34	10543
1061	501e127b349eb652bb093b86d7b702869c513acabf46e24402371f9b51b87a55	10545
1062	2bd29900ec583a59023fb188d9c191387cc6cb1815559cd13aa4cbecc1c42135	10548
1063	7fe2120e9531dbb3c1e90b775dd6b76739a51da70ca47b2acabdc98f396e1022	10553
1064	a836fbb6b9b9c5627d27797bde9a438e99280fc601e5efb719758bb7f110a2fa	10557
1065	467373a862afebee01d976313e973e5c77e6e288f143865845818edfe3cd9f2a	10563
1066	c7461bd90db554ef8c36c362ba8a63fa2785185985d9185dcb61c86daab8c631	10566
1067	9808a806d6d07218e903fcbe8f128d3e9a9d188b5d90b895bda1eb9055b9e7ab	10568
1068	aaaf5907c70f1946348d99b11278ce14e5a725158b6c86fc8837fd43cc3cb767	10575
1069	c40d2ad7a53bae9e3c285da1949cb8774b712082077f6d633ba37a662f57c409	10577
1070	7be401cd4d73b0dfdbed92d95475f2feb2d4a386bce1fed7829ac9e30e808895	10595
1071	7f6c8e5f16e1e93bccfb959210ea8f1a5fa85ef89bea374fbcbc765dbbcb3b73	10601
1072	c7f21fed871660cb0d0c9fae1226fc1f0f6d634ea1a9f2aa2e0d9a709a3202bd	10602
1073	fc73d10ea748972f4212813c775bc243047471ef7c0a0d4b9db9aac6724837f3	10624
1074	fb970bd5eaceb717f1092bfe4c4bfad5aa5f3747b9d8c16c02e7b67241880367	10635
1075	bea8c4af0d91f51d09461379ebcb06c78d110c1b69d5dcdac8e100298fb84a81	10645
1076	fe5677c052b5d76a985afb088f3a95aceac21e5f47fc59219838ad746931c1d4	10646
1077	1e43c9e0f291fdc3dda50db8c978a8244c92e0d54fb51a095e9050893eeef5f7	10651
1078	c6a8ae3e60bec330a498a49afb75849af30a0439508d1e8ff8fd9544dc549b3d	10697
1079	b537f12c136f886d74d52aaa518d6128a5e8e403fff14958b2d9b8f29263ff10	10718
1080	155250c26c6199a10eb7f3ccce8e00ad3928bd200061559c81c3df56973303d7	10726
1081	6810da375f6dd4d9996c353aa635cf3bccc28a8fde50dc9bb20056e6dbac3ced	10732
1082	e5f78928ccaf22c87a354995d4825429b579fce9f2a38d73579f256fef49d1ec	10737
1083	13927900da606e16eb5ce9b351d366ae298ff9107713acd52f1058fc864f7c14	10742
1084	1b7db62e3355b597cc3648dbfb38cae7436d107b4ebb34c12d94fbc9e9348dc0	10743
1085	15000b8bd735038d6abdbbacaf8dc93c786d1f345083b6ccd78a056f0d0140a0	10766
1086	368536a2d37b02991bf6ae0f04840368bc6f895f87da90a39cc84d277b79f3fd	10769
1087	17a8855c8dc6eb373f6860297256f99f48d78563e58d9ff491223539af04462c	10774
1088	97d986e40146ece3149c1ed4d961417cfdfe875a8bb9c78b7dbaea37ae787c06	10794
1089	14bf16cf3a2dc15213ad05ba6610ed511410393db390d2b12c35de6cf1e79485	10808
1090	e4d41699d7104079e4a33390cb82a44f267be3f18b7b0ca4d6dd8d9eef1172a8	10811
1091	21797458ac8456ca84a76f15898d1dd14b649f66f8447eec753f558602510856	10815
1092	2be1fa47e4758ba13a19a6ea7e16e6b19404a3169da6bae4dae492e5eef5aad3	10817
1093	45719d594af3438bc1685ccb41edd6baceb482f9d98afd648812f583bd257e37	10833
1094	e4f912162c5b61fe6e210338d4d04db88ede842e38807535695ee9a3dc314bce	10835
1095	ff178e0ddd3e3bc3df5afdf90bba56fb984d9a4059f2e5e81bd8aa1f5ae5875a	10839
1096	cafe10b03cdd0e4e34ebf86b96bc51f129c1796efc6b3ec5631162f5b4039289	10866
1097	b9f53882a7d3d1637cd498bb3f4e606d2a7406e2ad889d8322bcd70ee8f91ffe	10874
1098	cb0c3b6876e93fd41d2ca1f15ad378e8da07118687047873ed75a667c1e22668	10882
1099	14faa634dc992a3b502d2485c8a9f9898ee25ba04e890a1e5c9d3e9240de3ff4	10897
1100	943bedb6570438878109e2e70a6bccab53745ceef77e3eca284cf8c748b72e23	10898
1101	5d84998e20480510e8e7a912f0a9437805962700c734f4e0039746174b2ee95d	10911
1102	e6ef4096ee406ec63fe9068220f9cb6503855591341ba9e7a93ae2a86a213492	10920
1103	86e80e9bc4551241abb320a4b58d88039f0dbbbc316ca9cd8cdd2f22209c25c1	10922
1104	f7f6271767846a325a852d2de5a7d57be0899065aaa3d1f87fdcb89822310b68	10945
1105	14896e7dcbb8c521deb683b4950cebb434fcca31468b064abf96f2db2df6b9f3	10948
1106	41b46876495669804fec1c59ed8c8c9ad14ffba0bae63483264d2f73f0bff538	10949
1107	7a76a90ab0cae5b2b61ffe76960c93172f415855c57fd6d9c5198aec81834ce1	10955
1108	244fb76281d0637984079c37a05de0b03ca7f0d2af1868840dc42df709168514	10977
1109	1f240c0fd77d87630cbb6e787df304f6bf06fbeebdf0ca75d807cc3520224b94	10994
1110	bdbf95e2cd628a71b35154cb451c105caf706f63d676d6b5a99124068fbf3a30	10998
1111	e34a47e655884c95fcd66eaf10b33d46f6255eb086e309a661fec84fdfe485a8	11002
1112	99ef9b21e9c04cc3f774d38106de586619cc9b605e180facde9a6ace9ee739c9	11008
1113	29f8f6bf8c41e37a3ffac576aaed383358a835db0b295b84801af3523bdc145e	11011
1114	acbb2f7b0d64350fcf9c6269853d8696c04fb4ad69e59e635a51d9a01e7dbafa	11016
1115	6149bd3a867c02fd9102a553ccd0d9933a1caf8c8b8b497c62074a04a925234a	11021
1116	71b70bbfd6ead3872f33d1d2eb8a961101dc6ce72f50d8d98561fcaf9b01a7f8	11031
1117	944f122412dc883eabddb0b81308ad0c12d8427444b54cbd9a4dc260a394b7dd	11050
1118	8e473a275e6c3efbe26e5b92074b1381fe91e45ec3dda8b57eecd3536ca992d0	11067
1119	623505fd3c06a0b293cdb20b2c30b06565b1b49cd9aab19d093b23e28eb851c7	11070
1120	2a8493ce038d6f6676f57f7fc956e2aa08ed4d3c33b492a2ec3993583230044b	11077
1121	fd2bdad3760ecfd2520d6596351a5606ca3b72f1126896f54a3abe5dc094399b	11103
1122	d4512041366f3bba0b99f9abcbd213ba2bdb16499478fdedf8d1846e7f950124	11116
1123	493781fb892678d520d31dfa9775f4632247f5c120b41dfdb9aaa93615004eef	11133
1124	9b04ac2dc692aca8027ac57ccd7e012d1ffce34faa377b0e5d4660d19f1e0ca4	11140
1125	32bb390589d77ed4358997d0db14dd5b04e4c31b45c3de5a04320a054a9bd7aa	11152
1126	9e44a2f41f1906ae98572b4e50df678d8c83ee6e6ccf0903568a4268fd52bf85	11161
1127	5e172cbcefff0817428b51793d9cef87db5078c71e9364821777a849425e1a42	11190
1128	fc92430769027c471c79b11437696332d755bea75a77d186115d1959ec861209	11192
1129	d92afed35aa0afb8c16eacf7b7f3058931a4c2e2b31451b679b9856d3af71b72	11209
1130	5b3a57a95777f65666f5e9c93b66a1543689719a555625c6e53b3d932164da6c	11215
1131	0c39928b7573d45fd46a3097f3518aa528e416402d77fc1d5de800c820aa6a28	11228
1132	fbf2fd639b2f15681ee0adfa63e8205e22687e326501c421dcbd973a902eaef8	11237
1133	f7361f9b8b308366f3d376d9ab81bf6e4fca6f795ddc09dfcf3213b7c67ae692	11269
1134	1c0178be32c69146fdfe3be453ee1b98441fb1886829ecb32ea145ab2ded433c	11283
1135	8c85c77c05c188dd3fb4d46ada692b678c42d04efbd28c1496ae0337821d0f18	11300
1136	482b2846fd55a460b2d757bed743d177312218ad9a831b756ca89b7224e275c0	11321
1137	4b40c4e2ae746e0ad2ebf1553926397ea3873d4fa7d9495aa01a26ed924c8c0a	11322
1138	88ee9b25c637d55ff0535fd04c852e531fee7e9ea74c94ba1b9776f3da999c46	11324
1139	036eb170dc1f2d7b716a59e8e107796d7dce18513f03cd533608dee16d02d6a7	11329
1140	1d70520243db5e658ad84bfdc04052d86ddf6c61459839307a8c344b4e9dbd77	11332
1141	b8cab317f3f3b9bfd8d0986f10e839c8b60b640e521b9a7c5ab8287f9d35a33c	11333
1142	e073492d67c601a3b550d4d4cc39360f5e9f1d1ab5f9bc61fbb94e10106b5f03	11338
1143	19ef4f78e602d35caeae2657f97a30f0d41b84f524a1598f027c4914f98b7f65	11354
1144	a92afa474e62b2d8e625806fdc8cdcef6e3b7fde74d9ae436787aa6eba1d6d6a	11358
1145	6024798922f3ec078a8edc4136425619fdbf6791eebd58f75612562c36a2ae1b	11365
1146	37764f92b4a17f5be97d1a4dbf3964a88736748aa1dd240172b57991ae36919b	11375
1147	8a58a6cee6cfc2ea609c07a0bc1a36a793c8b85bde312359694dcf60f39cf34c	11393
1148	919a0248cc5e82959ac848032ffeaec822e70cc42e3fe6bdcbd78b966d050de5	11397
1149	65d85bc46e35183a00b86c0c41e9256902482b459f03b1d46509f1a710a2cd4a	11399
1150	17c10bc8e5da1b7b6a2d18db3994d9d4850c255e84db5c1b1241e556726e443e	11400
1151	1e1754f128177ff181f9897cb5ad6b35da031dfedefba0ce98b67e20bf5f3c08	11429
1152	7dd09de95cf485d7867489ec21c6385e2cc2ec1d648bf2b7605a453550cd03f2	11454
1153	b5629e7c54ffb73a34804e792b6ebefdf555e6d24aca2d67fb7b1e360bf72bf8	11457
1154	bd50b90578163212eced29591d060e7a0fec62be012c93d186d7bbb7aa258bbe	11477
1155	85ed9a3016c40779a5ed1e6124282d16881653f76a43b216032dd4ccd3dfe22e	11484
1156	c33d60069fcc3365af1790fc08808eb8e856a2c35eadba9f899a54a7f787262c	11491
1157	0d16701298bc9c8a3455fd52ac12104a8dd8f19cb81ddabfc2213a47ea310b38	11515
1158	9934eb7d7783bcfb17d967987f3e8d97c7e24bbfa8b6599cab1b31841ba62855	11527
1159	829ab23dbcad80abc94a01c267acfeac20f5ed541c62ce96cac7bb33545b9e5e	11551
1160	3a4932ff26a275071cc51dbafd4c2132a035f68387b0110ebd200735cf0ba37b	11552
1161	55e94be9a93717466325f551d5234d78bdad8af5b1bc5026c4e5a77b8d6086e7	11554
1162	d4aad574e7232fcefba1fa5857977f9b17029fe7427015d4b20b6d15baf12563	11561
1163	66dc3b059e75a550f75ac1d2d955c11286889fdb26092626bda0ce63328f616b	11562
1164	7968084f2048bd96766f68d6703f9a973cb433d711ca0bf8b5df33d0de4d234f	11567
1165	3c5cd743eaf0ecea5aa1c5abf233c77f95b8ebd2c916450254181b31fdfd4b28	11569
1166	d34095b89100b2f68926f13cd535254cc5317a446b949bbdb627ad4c61c446ed	11576
1167	9b57f6b4dcebe7269a4b6b8cdd8eb66e377c7c4edbc66061c8f9d30c99e8e7f6	11578
1168	c0008950180c1a5240c6e50e8894a58fb5ee87756725fd650cce8950df846c6d	11580
1169	f2af3df9b9cd9b5ff60949db8ec1a691091d3e4727df50d69617f670d79e5b14	11581
1170	80df3625fcd6c59e52ac93e67ec3358feab7231bcd50fa3064b9c615c5aa8f9c	11639
1171	b4208a46305291f8355c8a886915f96b4642f961d6dac03a5a721efaab2044d6	11640
1172	f745833715f97da49efdbb8412d0b35c65da7520bec340f280d13044796c0e38	11641
1173	674d91e5dc1133e3e41eec0089159d4faa788a2b83f8ce128da8e341e16e2d63	11674
1174	c227443c9d2d444f53405b46047d3e0489b281e26c842980cee2a12e36e94915	11676
1175	1f3c84c595fcab5440ec08f842ae9420619e6bc128e16ba2b065616d188a2d98	11698
1176	5cbbfc8184331d72e0dffbfcc67d5c4007f8d4ad5f639fa0c7818387cd71fcdb	11700
1177	91647f4997facc8090f8bd1b57f4f38a87a07723628d34fa3a3edc6b5183f939	11715
1178	7bd8777fe5c208e3a62b88fc9d43a7367f7a00018d4ea3aba734cdc4c5aeb628	11716
1179	f38af766508e0036432ed489aec2c9650022d80e850c7c6cad35fa3a8853a0ce	11718
1180	614efa29900aa314fa381133fcb300f2d3358eb7f32784170994a9374d2f7744	11733
1181	531dd4b3bdeb20d3bd307b0475cc4a8e73c57bdc7d2af82d226ff589f434d927	11735
1182	97794d980f5596029387233ae13e5ebdaaf4df60ffd4818c0a84383bd8e89275	11743
1183	ffc3f38d56c4b0964830ab5bc5e38e42d09a971d26f8223963b59057422cf62f	11745
1184	4a263c4a3d35fc1cf2f204c5a9197256f3008fe7eb20f3775bb8a6e3697a077e	11754
1185	43bac314698bf3ec5d876ef3d5970afefe4e868d7bba247f2fc064c178798890	11776
1186	f4fda8d62f9ebcc950d3081dab502b0527e3805c13a957eb19754abc72c51520	11781
1187	85e61cc874fe80e483bdc6f2c9339182ea147e3fdff7cbd252116317e29328e7	11782
1188	982b4b2845be7cdc4dcbedbfaabd5df9c51f4a64d78bad4b9d0c3725e32688ca	11784
1189	d1fbef788a4b5927fce0731257bc26b967192275328d1fa0e47a4d1abb84f89c	11786
1190	e0c25734c31c29d58fe09b95ffa51a0130c1d9cbd1cdfd0c42f280bf2b2e4aaa	11796
1191	3369dff9aab80024bc254ddd95bccaef3e6a9e238de5db391a82ad3a80725d8b	11801
1192	7a6326d040fd39d25459e5f270a052f180bde2568a218d9d63348f9d406d78e0	11803
1193	e0394e44bec86ab6503c9107ee54bcf11d08882ffa5d442d2a2715c549a69c63	11805
1194	992824f29555165c0743870f9182c3d3d6a6c010f57a7bb25f4e3961ed50639a	11809
1195	3076b20c3a43252fbc8fd5bf33b0d21b6b78fc4d52e592d75c6949b9d86efd5b	11822
1196	428deff979381e3b3074fb1fc65612d97b57ec5a93436f99bc73966e6cf64918	11835
1197	cdad348028f78fe56281dd72fa5303b0e773a628d2ecb216f13f2e66b7b8deae	11857
1198	e98aa0a8e8ad5cbefa0c0208bacf28723c30003f336e3d32c8b6ef68fb634b2b	11872
1199	c695c7e1523d27ee9a78d548d5a874b384adb1d512f8d24eaf0c42f42b26963b	11875
1200	64213f14a33641c82c938d32677324659c7a09c0b539f1fcd42ed256888456a1	11883
1201	cab349d1effb19937a81ba44b32894bc692d90bf15379289cdb9813929dde57e	11889
1202	80a25228f122f6001c8d5251d084d454284ebdba55a53db3765b95b4fac97dc8	11890
1203	293bd76237c5ad936a0c5befd513884b4713638e34de09ca555848483e477881	11894
1204	bf1ab1a1ebf71cf03e566234ba8641bce3c946c6834b32183915ca8efbfa3358	11895
1205	ee975fb8e2f40811a6479bc9318e94402faafdd5bf0a91c2053d05cf7cb8f46c	11897
1206	3d6398797ca4284347fe05073476a151db0f96bdd3ea85503cb21c4c582296bb	11903
1207	fe835f850e039437343a6d063e4ead013d7cac75337cd00bccd19d7d87887e89	11904
1208	cd8ced540e466b62d269951de343bcdc9ed5d5f34e19c4ab31508a9ed0ed4d69	11912
1209	8e61e24cd1cac795bdc4f97b965d42e77f1e15b84166ea1c1f502a8100a647d2	11919
1210	5a464e32fff3bd308aa5003adcfdce5411b78734926adfa12110d862b9343bb8	11931
1211	87ab4941ec9826709a0d421ebdff961be4a93c5d187e218cb3fa4c0cf55c025f	11957
1212	3032af9537fdffdd814daf5956caa681433c8f52f78ba663487b1d3c5617fa24	12006
1213	9fb5e617baa50111d99cf0873dac6776e20d9e497e08706bedd95f9e5afd4563	12013
1214	e7cd6e88fe27fdefce71dee053cb65aabfe46652aa262503a56d546b08b1b395	12024
1215	4c1072dcbac2d92c9e6cf15923f6bd7467e5fe29ba73d337bda6887001b978b3	12034
1216	7757a90f2ac8ccc8b83eb48c224f43b58129e93644a7ea5a7bbc7273aac3ed1c	12045
1217	d91b876fdc318a4ff92728e28dda61ac9c93efa6ba19420db403c660f0af0880	12056
1218	0316330ca2ddf7b53b8f837c05f8e18a4c398431f0ab6d98e0790ce78e199149	12069
1219	be8f3e967a53461e090abcbe450918820a9503319929e370f46a266deb37be5e	12081
1220	099c2b713cac79e92a0c9a761a16376dd13861c7cf91ab41496efe1f46244a8a	12087
1221	fb7ea2694fa483a9942fd6c74702222daf67d81e78f3061a7d48b99f3d7758c7	12112
1222	c2d57baae8b6b4754f02c0ba3c89b7a95d7c0bfc0f000001948b22a10b9d996e	12116
1223	8054f7bab15a9f8585f8ed0d6cc9db781240489634938d8d8378531a58d4b91e	12131
1224	7cb307e498eedb1233b5b96c7c96f3c44b22e4dc7f1d7f7e83048c4044b2ce15	12167
1225	495ab69822e44fca929e2084814ea4209ca4eb6208a6bfda962ea9f1ef34c2fa	12168
1226	b9744de554c10527b61c1155477edf3540ff0201a9dabe3af7a33d4a67d64f43	12171
1227	3c51681bc692e2e6147f36497e98708f1be986379294cc7a55bacfb7f8fa9910	12177
1228	090f72d7517c0325fc7d5fd5f5214ab3d0c450db1b6412ee42f02d7a71e904ea	12181
1229	e93636c149aa4b63d3e0087e5b88281a47d472e1695ad94465f1c31b3d683056	12193
1230	546f4dac34a4a2e4d8ecd3dac890282c0b8883efb83c6f4e077640fe08afddbd	12194
1231	815da8feb9f1204bcc4d5309049039e3375aaf6462d3f3f4cfd4dadcda562910	12204
1232	43af92c0de38ad1d31aad008383b323edd716a604e7d194b5d2583b8e42f8165	12223
1233	097ca6e30e4ae7720be036c4adb78eb96242fd496f9ff2f997ca0d68c00ad722	12224
1234	87f0925ccf436f1d742f8962c7ae884764fdc6b73cb7bbf64b8391cf4a2cdb5c	12251
1235	56eb20b8cf2b780cbe13124fc299371019a9b408e5f075cdcddd9f4046a530e1	12287
1236	e9cc4137823c843ebb14aa17c54d289c85fdb46b540df20f59ea079740d6a21e	12297
1237	fd5f58d4d933edf4b0aa90d858c6bdee0372f6d076b1cfc5a5d9601d27a57763	12298
1238	e77e3c8e599a92a51da7403766d924a26984e2faad49bf187df731a10b083205	12304
1239	ff856dbee9c2ba0445c21481f9bb2a06c718a0491086ec7970ef94573fa26bad	12319
1240	fccfe17c775f5e9d61eaa7c89855e829899dd7d6618553a5e59d028db517a505	12321
1241	0fb63b8bc30a809ebf0decf520b589bd5994752d4c92358314374250f4c8fdff	12328
1242	d064bb87b9964ef22235beb7fd7141772e2721d5127f9e934b941fc06786ff70	12339
1243	493c328bb6055d6851698f1cdea1e08db551d2328ca9969333388294de87a882	12359
1244	474d22e252b7106ab2b353bbcc6042b6c1498da718b2f60e13bc8b2547e53d68	12383
1245	18398771678c74677294030edcaf5ff3f570dfa44ee24b6d5514a90c15106e39	12384
1246	11b575bc04edd0f0e7add7ac107f7007a74fcc0134a95b8da56a2361ac9f4d16	12389
1247	4dede0a68bbe6e9ca8ca146d9dd5d81a6f821317c37ceffa186a9a3d1e15588b	12394
1248	01c3b4c02db82e882eb4d31720c76f17266dfeb4ebc3e97e6cc48b92028c50a2	12402
1249	c58bc667b57bab4eae03a19ead80fe8f56e3697b990aa3a9dfcd70740fa9bca7	12403
1250	188eb2fc65d8ca661f33ee7988572307016db039ca7daedc7f9fe9868a5250c2	12447
1251	3584e57ce1f646f05a952bb22ede27c22c8f8797008ef1fe2ead0ebfcbd643b6	12456
1252	b5f09b4e7e4988af566e16e6f8adcbf974ddbf59389f315e3aa0db41d70eb24b	12463
1253	4cb9f1b6d25578f962e90a96bea305a811d93c649c51eab2777d4ca493bc026f	12470
1254	9c1f0528122f709c518dcdbaa33823a36f202e9b32601c0493b6782a4e555f84	12477
1255	4de4c8c9cc24c04a46aa04f8a1135d1d827c4d5069b5f1a2be55b5d2c8010b3c	12484
1256	f34abd2856dbb69409b85e5a16bab172511d3051589db9549253920c4688b74b	12495
1257	50fb3e8b5f1cd82f71955206eaf06b8d540d03c023d41e07fb5b53549dec0153	12546
1258	af6fe74ad4073126f7c454c8cbc008e258065fa14d368cf311d427ac75d8262b	12563
1259	addc0566c37ab66c487f57896265bd7d1f108816092867116453d804ac39db62	12568
1260	022781404db546be69a0ec02295408b753e47489f986677aa9bdb54f8da27e91	12576
1261	02f464e12730065bc84ae83d57001199c2e1f0687b151c8060e663d344dada04	12582
1262	c11d47e191115ae10aea0c4dd65c18e59b36fbaf9ccdbaa1fdb4a0f183dd1878	12584
1263	055fd30c2926f8f1cd0516df7ccafaab629b3e00e76c803390990f23ee3cfd51	12598
1264	7da49fefa9025d87e685ef8835b99e901b1f5e024bcebdf818e4502981faf0be	12617
1265	c812aab52b689bd7099d9abded21462b9f65e017f06105e138cad8e4ea12e7a3	12619
1266	3d676009affc2ee59eb2c4b13ee3ac2ac503f5067ea4f9cc96ee820068e3a3d4	12667
1267	0dfaab44fbfa156fcf1439392dd325f739bea2f5cfa8b76a5baa7b818cba8274	12668
1268	d2968692aeaec7e60de06e5f1baf7ba012ea6203c0a1159d1cb618c016975f7c	12692
1269	ad3885aba492f8feae89f00692906f0a4ec53ba2172e50551b2cdf788056201f	12696
1270	d1b95616e389d01e46a228881c169a2cafe5c73b54ef4c5fb4b081ce0a5fcac5	12711
1271	43c82070b49cbf27008a542335316db01be33564c6766e54724edac0e9a41003	12738
1272	d7162ebc0900e4ea6ae67587a46c719af20ca43a6fc535ebf807f5688f783730	12739
1273	c21b2334f6f19d998f7d45d74356087667a08ad7a307964538089392738cd89d	12746
1274	315b62568193992521b9ea4ee10669c6db1359c32506d3459eff1ac9ab389f95	12755
1275	4e90215d67b95c140e43a3fa7ca9b3842a9765d58999665ca3248ac25bd83bc4	12767
1276	0976ed8ec1c35436d007c93c18ac24816d8fb1e7fc734247c7c4e99d19aa5fd5	12784
1277	5cf35898eea53593b15e81f617456cb223fb4d7b254437806737556bb9f5e259	12789
1278	f2f233b4e876af6867136922c15cf2dd6b115284ec5149fa38fea933b0e9f3c1	12793
1279	bb02779a87f6e7a98734cf3be18537bc8e6fce04025fa3ea8180cde4feee40ea	12796
1280	2394beed7e1f45139d7aeb84afba39fa464c8d48f03abacd20c88ffaaef8b9dc	12797
1281	4ea35175d968a169c6cfd60daacc741c3487751ea87423608c11b2b872cd8167	12813
1282	46fd49870e7f938da544271cfe4095b1e682d91b3d3b3a9b4860acbdd2be642f	12824
1283	1ab740ca940a3104827194a6dd56ba5b5b4fff924aae9da7e789dfbd2e344443	12831
1284	d372dd5df17e5fc0fb1b307647aaf279ace215094cc06bbb332b27f5358ffa07	12847
1285	d26cc202bb9326c030eda7659340ca286ea66eb1c6dc36d3612ca4b55c247d83	12861
1286	d3c6526a87b1abc34a7e64d257dcb82857a99a9b5a2b1fc5c8234f19fb744b4a	12864
1287	3448b6ee3df25d261eba773b5033f230b6d3e7860ef66cd92a605098e3169673	12880
1288	221ea0662ac6c0dedcac67263840abd33e9499a9517b5d3c3c699e152c2d22c0	12887
1289	7d649c1493c799eecf57d496268e0d9f5564fb8f74156d3b485350d506c876ea	12897
1290	629243b59bbbd1b46c5dac688fbd029ae846d3269e583412c2382bd1cfab0292	12909
1291	f138f81d96b3d55a75c3bc28e98bfa918d4da57f7da78cc66f36a3813d72bef1	12912
1292	0248c2129d781667e17df998b4217b071bb1d3b43be74e0840eaa049b8efb4f0	12930
1293	002dfbd5e81ea54e410c321033edeaebee7fc48270421405ae39a0a94c88824c	12934
1294	50e763349e81d6029d27be5fdaf45f1a1773e6fb991dd05cce0451b2003dfc1a	12940
1295	01109e4fe2d7ec8609fa2085ca4e0ba2f29c2b13983e26aa0d61590c0eb22025	12945
1296	31572bf89d92dd3d75d039cddf0673c96bb541947f63571bce49b3c25783d6ba	12947
1297	899108104ff85051fce78634362e3bda81d77373ea149b4c39ca1eccb96617a2	12949
1298	69815354e5c0439d3f4fca9341035d73f2a85c37bc8b606a04187854fd4d4765	12951
1299	65ab7cb2c06f62e2e32f6107741a41462f0a54e29f54b76e01ad3a1996eb7c65	12956
1300	e5a2ef30013619288457a3662b9e1817774cd6735aa681fe5d175b79dfd940a9	12959
1301	8ef482a8faa3a0090b2734f614c6cc3a66ce13cd81cfebc9882d0ae95dc4d0bc	12970
1302	6e681d9a4d66e042071173e733acbb72eaaec00b8bcd9795fb3d2924ea112219	12991
1303	94accc324d14bcdc8a6411ab85e368d5c200065d9d1e88cf5b23e5ed54680f33	13021
1304	d63979062df0b039cbed1e7d74bf05ace7ca6198b2da2d1421b26ff12a8b9805	13035
1305	a8b71c2f03c4de312eb36a9701efe7174389a4638db7b281ea1c0deec7cc2caf	13052
1306	f1dc1164a14f1e2c068b83d9ddc7f43d4435c8202b38adc609561e64c12f649f	13053
1307	9d1f12bd3ee6dd0fbd622862d088d0b7db58b7b4cf96f69cbb7113129cd0c8e4	13056
1308	47dbe9e2e5420c63cbddf362c4023e9db1e0cf1419f49e348d5e49d3c8bdfcfb	13061
1309	9f3f610b7042f25c8d406cb9a152dda4048203b5c9a38baf932721a34c97566a	13075
1310	f255e99a92674e7300d5e7907c0d0e03873f3f3db7cc16fa137fad0b4a6f50c0	13085
1311	c4fc5f6d37e462743fdfab2aa15a4b2b5140cdce9875b4e4330a363e454a3b9c	13118
1312	28374058cfcf35efe2897c9aedfb464296aacf88ead81c3cd03045d1ec50606a	13121
1313	8e2725063239906eafccdb6dbaa37247a9a831f5bea055051f755eb2decab47e	13132
1314	3f1db5c31412a498206d5a9370b0194a938a53760e10a653038afd3c24a84d42	13135
1315	1079163ae531974b927cb3e9d2ee82e2480e73a67aa6fb121505e5f8955a3f07	13140
1316	747ca5e131a4b8a2b8cc48e1f7a03529a90bd4b6652cef38b7929fb9b9100624	13150
1317	f7525c853b6963110104872fe95956a8b99692aeef39e57a50626682e7cf8672	13154
1318	cc2ddeb9e68c0cf18222a6ace7c905a13c1076c7f74f0879059d6a05144537aa	13164
1319	bf2fac6612e7aa10c61b16234f2199ef13f12d57b46a103dd2a6496099be5772	13173
1320	ac4abc4ee1305e5366371e2f4dac9fbd39308705b80c5e81ee733a97f33ef5a6	13175
1321	d8a713cdc11fbdeb78a227359c02badfecb457d311545100a8d15a6f117f9e90	13188
1322	3c3123b376ce17dc81a21aebd59bae12cd5579057ae1ae9caac38f9e6f8666b8	13218
1323	2b44a84a1b8d2c2c59641ee7b80d8b3d6881fe49376d99420b293dc262ab5525	13229
1324	ced92b6295504f2f5ce6ae3c12359ff3874294f1d6f42fe2faaeeb82fae30028	13235
1325	6996a2736fe82644058fa1d84fa5fee65ba02c6aa24c35b06667fd5cae452faf	13236
1326	38a75c15f5d0699f20326fceb04db18a25e0ca305fb9ef71aab74c8f4510369a	13238
1327	b26c8551524a160b3f6ab60377201aaccad3efeee444819cecfc52f967db89af	13248
1328	88584d994b68f0e8a4aa5ac1b1b103c14d9add1ed74d18e6fa696acb7d824101	13250
1329	0cce3b99bb81e1b4917904bfa0a5dc5da2c07a849596d2db3204ace27a6a1ad9	13288
1330	48b14129d47eb901afc9d35501da040daafbc6af8ca29ba9e6ed76b231df70a3	13300
1331	c088584dde9e508d924c9520701d207897bd868ce6bc0f6584d47eaf8f3e9c11	13316
1332	d50f6ea81b6791723face5afbdcff251c480166c102db11781c7da945e1cd126	13329
1333	8775084733c162f4bc082d426faff91719b234ad9b2c3f7725de6779da0ad65e	13330
1334	66bd94e7977359c1655d789d97ae88641528a21751785513b05290768ed06141	13336
\.


--
-- Data for Name: block_data; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.block_data (block_height, data) FROM stdin;
1308	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330382c2268617368223a2234376462653965326535343230633633636264646633363263343032336539646231653063663134313966343965333438643565343964336338626466636662222c22736c6f74223a31333036317d2c22697373756572566b223a2239373666656661396233333833303634383039633830326232343662353337633131346261633531303766373638646533653630626334303462623339346238222c2270726576696f7573426c6f636b223a2239643166313262643365653664643066626436323238363264303838643062376462353862376234636639366636396362623731313331323963643063386534222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3136776d72367972786b756e6c37636d653673376b6b68656e6d6567646161786b7032336330387472796c6c79796e786b7668707130776b783063227d
1309	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330392c2268617368223a2239663366363130623730343266323563386434303663623961313532646461343034383230336235633961333862616639333237323161333463393735363661222c22736c6f74223a31333037357d2c22697373756572566b223a2233613039306333333430346437633663353733613436636138393061363039653265653865623938663932626437393331323335323666313565616636666465222c2270726576696f7573426c6f636b223a2234376462653965326535343230633633636264646633363263343032336539646231653063663134313966343965333438643565343964336338626466636662222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31716c36766b7a7a7078346a33746a6b386d3638746871387767743366657a7a766d3461666573726e6170326433346538653764736c6672777479227d
1310	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313331302c2268617368223a2266323535653939613932363734653733303064356537393037633064306530333837336633663364623763633136666131333766616430623461366635306330222c22736c6f74223a31333038357d2c22697373756572566b223a2239373666656661396233333833303634383039633830326232343662353337633131346261633531303766373638646533653630626334303462623339346238222c2270726576696f7573426c6f636b223a2239663366363130623730343266323563386434303663623961313532646461343034383230336235633961333862616639333237323161333463393735363661222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3136776d72367972786b756e6c37636d653673376b6b68656e6d6567646161786b7032336330387472796c6c79796e786b7668707130776b783063227d
1311	\\x7b22626f6479223a5b7b22617578696c6961727944617461223a7b225f5f74797065223a22756e646566696e6564227d2c22626f6479223a7b22617578696c696172794461746148617368223a7b225f5f74797065223a22756e646566696e6564227d2c22636572746966696361746573223a5b7b225f5f747970656e616d65223a22506f6f6c526567697374726174696f6e4365727469666963617465222c22706f6f6c506172616d6574657273223a7b226964223a22706f6f6c3165346571366a3037766c64307775397177706a6b356d6579343236637775737a6a376c7876383974687433753674386e766734222c22767266223a2232656535613463343233323234626239633432313037666331386136303535366436613833636563316439646433376137316635366166373139386663373539222c22706c65646765223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22353030303030303030303030303030227d2c22636f7374223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2231303030227d2c226d617267696e223a7b2264656e6f6d696e61746f72223a352c226e756d657261746f72223a317d2c227265776172644163636f756e74223a227374616b655f7465737431757273747872777a7a75366d78733338633070613066706e7365306a73647633643466797939326c7a7a7367337173737672777973222c226f776e657273223a5b227374616b655f7465737431757273747872777a7a75366d78733338633070613066706e7365306a73647633643466797939326c7a7a7367337173737672777973225d2c2272656c617973223a5b7b225f5f747970656e616d65223a2252656c6179427941646472657373222c2269707634223a223132372e302e302e31222c2269707636223a7b225f5f74797065223a22756e646566696e6564227d2c22706f7274223a363030307d5d2c226d657461646174614a736f6e223a7b225f5f74797065223a22756e646566696e6564227d7d7d5d2c22636f6c6c61746572616c73223a5b5d2c22666565223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313739383839227d2c22696e70757473223a5b7b22696e646578223a322c2274784964223a2231626239323064333839323661353964383035323839323037333031383265346566633462396334363235313630346632316563316335393664306464616563227d5d2c226d696e74223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c226f757470757473223a5b7b2261646472657373223a22616464725f746573743171727868797232666c656e6134616d733570637832366e30796a347474706d6a7132746d7565737534776177386e30716b767875793965346b64707a3073377236376a7238706a6c397136657a6d326a6767323437793971337a7071786761333773222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2233303030303030227d7d7d2c7b2261646472657373223a22616464725f746573743171727868797232666c656e6134616d733570637832366e30796a347474706d6a7132746d7565737534776177386e30716b767875793965346b64707a3073377236376a7238706a6c397136657a6d326a6767323437793971337a7071786761333773222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2234393939393936383230313131227d7d7d5d2c22726571756972656445787472615369676e617475726573223a5b5d2c22736372697074496e7465677269747948617368223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c6964697479496e74657276616c223a7b22696e76616c69644265666f7265223a7b225f5f74797065223a22756e646566696e6564227d2c22696e76616c6964486572656166746572223a31343532357d2c227769746864726177616c73223a5b5d7d2c226964223a2231326563653064633930626336336332366337373837333062316164323138323065376165346230646636336233383766393735316661626539303732356535222c22696e707574536f75726365223a22696e70757473222c227769746e657373223a7b22626f6f747374726170223a5b5d2c22646174756d73223a5b5d2c2272656465656d657273223a5b5d2c2273637269707473223a5b5d2c227369676e617475726573223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b2263396237386631316366356165383965363837303730376233333731623265613930323837356264613266623439363332613036353539393966313039353963222c223030643637666365666638336232323765326636646638643737336330313436376264646361356130666566313538313638666238333932626663393738373565656338313730653462643534313037643562306132396237393538633637346661613930643437353461363666346562313465396235363064623365353035225d2c5b2262316237376531633633303234366137323964623564303164376630633133313261643538393565323634386330383864653632373236306334636135633836222c223332303730333666346635383037373762633931376232386266666230313530613465376435303932633063323761396332613736333064393434383234616638343434366430616164373836353836396134333436386562643331326233313466353864643938373837633161396534353664613333376564343635383036225d5d7d7d7d5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313739383839227d2c22686561646572223a7b22626c6f636b4e6f223a313331312c2268617368223a2263346663356636643337653436323734336664666162326161313561346232623531343063646365393837356234653433333061333633653435346133623963222c22736c6f74223a31333131387d2c22697373756572566b223a2263363032313464323738383530616636663866393738353761336532343039353337633235613636323535363331373832313966336431366531636365313631222c2270726576696f7573426c6f636b223a2266323535653939613932363734653733303064356537393037633064306530333837336633663364623763633136666131333766616430623461366635306330222c2273697a65223a3535342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2234393939393939383230313131227d2c227478436f756e74223a312c22767266223a227672665f766b31777a76346d7961786c35676a6170717666746a636364783374636c70307039687972356b6c756c6e363377397961327570326371706379796779227d
1312	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313331322c2268617368223a2232383337343035386366636633356566653238393763396165646662343634323936616163663838656164383163336364303330343564316563353036303661222c22736c6f74223a31333132317d2c22697373756572566b223a2234333264636130656533373130613564363634336262333239323464333432633237653966313431383061653335646332376162376163306236346632643539222c2270726576696f7573426c6f636b223a2263346663356636643337653436323734336664666162326161313561346232623531343063646365393837356234653433333061333633653435346133623963222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3134636b346c68306e6637637733666e6e633973727968327a676830646437757a72666a636e63766a636434616a73656767653073677835337175227d
1313	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313331332c2268617368223a2238653237323530363332333939303665616663636462366462616133373234376139613833316635626561303535303531663735356562326465636162343765222c22736c6f74223a31333133327d2c22697373756572566b223a2239373666656661396233333833303634383039633830326232343662353337633131346261633531303766373638646533653630626334303462623339346238222c2270726576696f7573426c6f636b223a2232383337343035386366636633356566653238393763396165646662343634323936616163663838656164383163336364303330343564316563353036303661222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3136776d72367972786b756e6c37636d653673376b6b68656e6d6567646161786b7032336330387472796c6c79796e786b7668707130776b783063227d
1314	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313331342c2268617368223a2233663164623563333134313261343938323036643561393337306230313934613933386135333736306531306136353330333861666433633234613834643432222c22736c6f74223a31333133357d2c22697373756572566b223a2237616235643232623537306434383039306338636265323637396630656261343264376533636634343830366333623134386337303631656338376438653033222c2270726576696f7573426c6f636b223a2238653237323530363332333939303665616663636462366462616133373234376139613833316635626561303535303531663735356562326465636162343765222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b317371307739616c706b72303273377063366537337a3068336a723273686a736c7930643734366c756b3233756361337536783271753477646b6a227d
1315	\\x7b22626f6479223a5b7b22617578696c6961727944617461223a7b225f5f74797065223a22756e646566696e6564227d2c22626f6479223a7b22617578696c696172794461746148617368223a7b225f5f74797065223a22756e646566696e6564227d2c22636572746966696361746573223a5b7b225f5f747970656e616d65223a225374616b654b6579526567697374726174696f6e4365727469666963617465222c227374616b654b657948617368223a226530623330646332313733356233343232376333633364376134333338363566323833353931366435323432313535663130613038383832227d5d2c22636f6c6c61746572616c73223a5b5d2c22666565223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313639393839227d2c22696e70757473223a5b7b22696e646578223a312c2274784964223a2231326563653064633930626336336332366337373837333062316164323138323065376165346230646636336233383766393735316661626539303732356535227d5d2c226d696e74223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c226f757470757473223a5b7b2261646472657373223a22616464725f746573743171727868797232666c656e6134616d733570637832366e30796a347474706d6a7132746d7565737534776177386e30716b767875793965346b64707a3073377236376a7238706a6c397136657a6d326a6767323437793971337a7071786761333773222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2233303030303030227d7d7d2c7b2261646472657373223a22616464725f746573743171727868797232666c656e6134616d733570637832366e30796a347474706d6a7132746d7565737534776177386e30716b767875793965346b64707a3073377236376a7238706a6c397136657a6d326a6767323437793971337a7071786761333773222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2234393939393933363530313232227d7d7d5d2c22726571756972656445787472615369676e617475726573223a5b5d2c22736372697074496e7465677269747948617368223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c6964697479496e74657276616c223a7b22696e76616c69644265666f7265223a7b225f5f74797065223a22756e646566696e6564227d2c22696e76616c6964486572656166746572223a31343537357d2c227769746864726177616c73223a5b5d7d2c226964223a2266363063343133613866626631663962333439356438356431613132626335323832313437326430306363353064656661393139396166633764653435643866222c22696e707574536f75726365223a22696e70757473222c227769746e657373223a7b22626f6f747374726170223a5b5d2c22646174756d73223a5b5d2c2272656465656d657273223a5b5d2c2273637269707473223a5b5d2c227369676e617475726573223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b2263396237386631316366356165383965363837303730376233333731623265613930323837356264613266623439363332613036353539393966313039353963222c223864353265623565326264646136363738326131653362343065366433363137646365643165663965356162303232363938353661316131386361653731333164623966356662393435613238653466636532386466383239383130396637373938643236383665306439316436326232306337303366373761663433323034225d5d7d7d7d5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313639393839227d2c22686561646572223a7b22626c6f636b4e6f223a313331352c2268617368223a2231303739313633616535333139373462393237636233653964326565383265323438306537336136376161366662313231353035653566383935356133663037222c22736c6f74223a31333134307d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2233663164623563333134313261343938323036643561393337306230313934613933386135333736306531306136353330333861666433633234613834643432222c2273697a65223a3332392c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2234393939393936363530313232227d2c227478436f756e74223a312c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1316	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313331362c2268617368223a2237343763613565313331613462386132623863633438653166376130333532396139306264346236363532636566333862373932396662396239313030363234222c22736c6f74223a31333135307d2c22697373756572566b223a2265383231613831333530386461366561646334343661646165653962376130626462636663376139376161396339636531383462343839636239386166376130222c2270726576696f7573426c6f636b223a2231303739313633616535333139373462393237636233653964326565383265323438306537336136376161366662313231353035653566383935356133663037222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b316c75703538346d7a6a32677873387536367968666a6d7a6837787835716b3430396b6d71683574636d6d3676656d333265756a736d7478706b65227d
1317	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313331372c2268617368223a2266373532356338353362363936333131303130343837326665393539353661386239393639326165656633396535376135303632363638326537636638363732222c22736c6f74223a31333135347d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2237343763613565313331613462386132623863633438653166376130333532396139306264346236363532636566333862373932396662396239313030363234222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1318	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313331382c2268617368223a2263633264646562396536386330636631383232326136616365376339303561313363313037366337663734663038373930353964366130353134343533376161222c22736c6f74223a31333136347d2c22697373756572566b223a2263393534376665666362323631363533643565396431326463616333383234323962356139306463306537636331633936313333393931366137646335643238222c2270726576696f7573426c6f636b223a2266373532356338353362363936333131303130343837326665393539353661386239393639326165656633396535376135303632363638326537636638363732222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31386771396e6630687468393539346573366e637361617a746474377977386d66616d75736b6b306a646875726e6b7170386a6671737737767779227d
1319	\\x7b22626f6479223a5b7b22617578696c6961727944617461223a7b225f5f74797065223a22756e646566696e6564227d2c22626f6479223a7b22617578696c696172794461746148617368223a7b225f5f74797065223a22756e646566696e6564227d2c22636572746966696361746573223a5b7b225f5f747970656e616d65223a225374616b6544656c65676174696f6e4365727469666963617465222c22706f6f6c4964223a22706f6f6c3165346571366a3037766c64307775397177706a6b356d6579343236637775737a6a376c7876383974687433753674386e766734222c227374616b654b657948617368223a226530623330646332313733356233343232376333633364376134333338363566323833353931366435323432313535663130613038383832227d5d2c22636f6c6c61746572616c73223a5b5d2c22666565223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313735373533227d2c22696e70757473223a5b7b22696e646578223a312c2274784964223a2266363063343133613866626631663962333439356438356431613132626335323832313437326430306363353064656661393139396166633764653435643866227d5d2c226d696e74223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c226f757470757473223a5b7b2261646472657373223a22616464725f746573743171727868797232666c656e6134616d733570637832366e30796a347474706d6a7132746d7565737534776177386e30716b767875793965346b64707a3073377236376a7238706a6c397136657a6d326a6767323437793971337a7071786761333773222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2233303030303030227d7d7d2c7b2261646472657373223a22616464725f746573743171727868797232666c656e6134616d733570637832366e30796a347474706d6a7132746d7565737534776177386e30716b767875793965346b64707a3073377236376a7238706a6c397136657a6d326a6767323437793971337a7071786761333773222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2234393939393930343734333639227d7d7d5d2c22726571756972656445787472615369676e617475726573223a5b5d2c22736372697074496e7465677269747948617368223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c6964697479496e74657276616c223a7b22696e76616c69644265666f7265223a7b225f5f74797065223a22756e646566696e6564227d2c22696e76616c6964486572656166746572223a31343630347d2c227769746864726177616c73223a5b5d7d2c226964223a2234303565336335666362656535376134666632326332313662336131323461626638303836303332313763326637616166386261323534663764653561306561222c22696e707574536f75726365223a22696e70757473222c227769746e657373223a7b22626f6f747374726170223a5b5d2c22646174756d73223a5b5d2c2272656465656d657273223a5b5d2c2273637269707473223a5b5d2c227369676e617475726573223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b2263396237386631316366356165383965363837303730376233333731623265613930323837356264613266623439363332613036353539393966313039353963222c223062633130643139323466313435303839616165616534633436316565346463313361316431663463633465363463356433653334353163343132366132386264626566353635353033336338616264346664653335666134306663313061323762363334313036346139633130623734303538646632666438623730633066225d2c5b2262316237376531633633303234366137323964623564303164376630633133313261643538393565323634386330383864653632373236306334636135633836222c223830333132666365343131653636333330343732643233623831313233616631316166313763663334303133643661366133373536663437343139653665393430396561313537336535663361323531613835386231363735636563646663616534396531363661303633666531623339343830363033383534393931353037225d5d7d7d7d5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313735373533227d2c22686561646572223a7b22626c6f636b4e6f223a313331392c2268617368223a2262663266616336363132653761613130633631623136323334663231393965663133663132643537623436613130336464326136343936303939626535373732222c22736c6f74223a31333137337d2c22697373756572566b223a2231333065316633353036623739626666383963653632383433363035343639363465663961626338633131383630653938636433613866393830313730653530222c2270726576696f7573426c6f636b223a2263633264646562396536386330636631383232326136616365376339303561313363313037366337663734663038373930353964366130353134343533376161222c2273697a65223a3436302c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2234393939393933343734333639227d2c227478436f756e74223a312c22767266223a227672665f766b3130353370677967346c396336676d6a34636c367632686a366370743930373070786468716635763575647937787379743037677163326a6d7975227d
1320	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332302c2268617368223a2261633461626334656531333035653533363633373165326634646163396662643339333038373035623830633565383165653733336139376633336566356136222c22736c6f74223a31333137357d2c22697373756572566b223a2263393534376665666362323631363533643565396431326463616333383234323962356139306463306537636331633936313333393931366137646335643238222c2270726576696f7573426c6f636b223a2262663266616336363132653761613130633631623136323334663231393965663133663132643537623436613130336464326136343936303939626535373732222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31386771396e6630687468393539346573366e637361617a746474377977386d66616d75736b6b306a646875726e6b7170386a6671737737767779227d
1321	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332312c2268617368223a2264386137313363646331316662646562373861323237333539633032626164666563623435376433313135343531303061386431356136663131376639653930222c22736c6f74223a31333138387d2c22697373756572566b223a2265383231613831333530386461366561646334343661646165653962376130626462636663376139376161396339636531383462343839636239386166376130222c2270726576696f7573426c6f636b223a2261633461626334656531333035653533363633373165326634646163396662643339333038373035623830633565383165653733336139376633336566356136222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b316c75703538346d7a6a32677873387536367968666a6d7a6837787835716b3430396b6d71683574636d6d3676656d333265756a736d7478706b65227d
1322	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332322c2268617368223a2233633331323362333736636531376463383161323161656264353962616531326364353537393035376165316165396361616333386639653666383636366238222c22736c6f74223a31333231387d2c22697373756572566b223a2231333065316633353036623739626666383963653632383433363035343639363465663961626338633131383630653938636433613866393830313730653530222c2270726576696f7573426c6f636b223a2264386137313363646331316662646562373861323237333539633032626164666563623435376433313135343531303061386431356136663131376639653930222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3130353370677967346c396336676d6a34636c367632686a366370743930373070786468716635763575647937787379743037677163326a6d7975227d
1323	\\x7b22626f6479223a5b7b22617578696c6961727944617461223a7b225f5f74797065223a22756e646566696e6564227d2c22626f6479223a7b22617578696c696172794461746148617368223a7b225f5f74797065223a22756e646566696e6564227d2c22636572746966696361746573223a5b7b225f5f747970656e616d65223a22506f6f6c526567697374726174696f6e4365727469666963617465222c22706f6f6c506172616d6574657273223a7b226964223a22706f6f6c316d37793267616b7765777179617a303574766d717177766c3268346a6a327178746b6e6b7a6577306468747577757570726571222c22767266223a2236343164303432656433396332633235386433383130363063313432346634306566386162666532356566353636663463623232343737633432623261303134222c22706c65646765223a7b225f5f74797065223a22626967696e74222c2276616c7565223a223530303030303030227d2c22636f7374223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2231303030227d2c226d617267696e223a7b2264656e6f6d696e61746f72223a352c226e756d657261746f72223a317d2c227265776172644163636f756e74223a227374616b655f7465737431757a3579687478707068337a71306673787666393233766d3363746e64673370786e7839326e6737363475663575736e716b673576222c226f776e657273223a5b227374616b655f7465737431757a3579687478707068337a71306673787666393233766d3363746e64673370786e7839326e6737363475663575736e716b673576225d2c2272656c617973223a5b7b225f5f747970656e616d65223a2252656c6179427941646472657373222c2269707634223a223132372e302e302e32222c2269707636223a7b225f5f74797065223a22756e646566696e6564227d2c22706f7274223a363030307d5d2c226d657461646174614a736f6e223a7b225f5f74797065223a22756e646566696e6564227d7d7d5d2c22636f6c6c61746572616c73223a5b5d2c22666565223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313833323737227d2c22696e70757473223a5b7b22696e646578223a302c2274784964223a2264636632313739303530323764663035633833633034643838393434313131303430363135386531303664633435323661313836616538613662323265393434227d5d2c226d696e74223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c226f757470757473223a5b7b2261646472657373223a22616464725f7465737431717230633366726b656d3963716e35663733646e767170656e6132376b326667716577367763743965616b613033616766776b767a72307a7971376e7176636a32347a65687273687836337a7a64787632347833613474636e666571397a776d6e37222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2233303030303030227d7d7d2c7b2261646472657373223a22616464725f7465737431717230633366726b656d3963716e35663733646e767170656e6132376b326667716577367763743965616b613033616766776b767a72307a7971376e7176636a32347a65687273687836337a7a64787632347833613474636e666571397a776d6e37222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b223062666265633832356533346234346238633263626266626434613964353235323664373731303633333361313133356133323331383961222c7b225f5f74797065223a22626967696e74222c2276616c7565223a223133353030303030303030303030303030227d5d2c5b2230626662656338323565333462343462386332636262666264346139643532353236643737313036333333613131333561333233313839613734343235343433222c7b225f5f74797065223a22626967696e74222c2276616c7565223a223133353030303030303030303030303030227d5d2c5b2230626662656338323565333462343462386332636262666264346139643532353236643737313036333333613131333561333233313839613734343535343438222c7b225f5f74797065223a22626967696e74222c2276616c7565223a223133353030303030303030303030303030227d5d2c5b2230626662656338323565333462343462386332636262666264346139643532353236643737313036333333613131333561333233313839613734346434393465222c7b225f5f74797065223a22626967696e74222c2276616c7565223a223133353030303030303030303030303030227d5d5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2236383136373233227d7d7d5d2c22726571756972656445787472615369676e617475726573223a5b5d2c22736372697074496e7465677269747948617368223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c6964697479496e74657276616c223a7b22696e76616c69644265666f7265223a7b225f5f74797065223a22756e646566696e6564227d2c22696e76616c6964486572656166746572223a31343632387d2c227769746864726177616c73223a5b5d7d2c226964223a2235333830346365363834353437633261356133633634373536366266386237363131626363386632346137386664306163383535366134336630356665306233222c22696e707574536f75726365223a22696e70757473222c227769746e657373223a7b22626f6f747374726170223a5b5d2c22646174756d73223a5b5d2c2272656465656d657273223a5b5d2c2273637269707473223a5b5d2c227369676e617475726573223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b2238343435333239353736633961353736656365373235376266653939333039323766393233396566383736313564363963333137623834316135326137666436222c223066396332313536633431383635646261373634353466356631346433393834383035346433353730323137646237303239363138313337316438316663646165383661633735303331653430623536356261373132323065326231313930383961333766643039363535633631663834353933653738613439313461333030225d2c5b2261323864383864383665633264633963626666373466613030643362363534636330343734396430643165396265303934343762663530386163613330353030222c223765373166646465356432626234343266396634613636376438333135393930623232396337373839626537626161373361353933623563353336616230386639363937643732346638643266343837613264303738343963313839376663396339343365656633376338633163666332343939333037613832333636343061225d5d7d7d7d5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313833323737227d2c22686561646572223a7b22626c6f636b4e6f223a313332332c2268617368223a2232623434613834613162386432633263353936343165653762383064386233643638383166653439333736643939343230623239336463323632616235353235222c22736c6f74223a31333232397d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2233633331323362333736636531376463383161323161656264353962616531326364353537393035376165316165396361616333386639653666383636366238222c2273697a65223a3633312c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2239383136373233227d2c227478436f756e74223a312c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1324	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332342c2268617368223a2263656439326236323935353034663266356365366165336331323335396666333837343239346631643666343266653266616165656238326661653330303238222c22736c6f74223a31333233357d2c22697373756572566b223a2263393534376665666362323631363533643565396431326463616333383234323962356139306463306537636331633936313333393931366137646335643238222c2270726576696f7573426c6f636b223a2232623434613834613162386432633263353936343165653762383064386233643638383166653439333736643939343230623239336463323632616235353235222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31386771396e6630687468393539346573366e637361617a746474377977386d66616d75736b6b306a646875726e6b7170386a6671737737767779227d
1325	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332352c2268617368223a2236393936613237333666653832363434303538666131643834666135666565363562613032633661613234633335623036363637666435636165343532666166222c22736c6f74223a31333233367d2c22697373756572566b223a2237616235643232623537306434383039306338636265323637396630656261343264376533636634343830366333623134386337303631656338376438653033222c2270726576696f7573426c6f636b223a2263656439326236323935353034663266356365366165336331323335396666333837343239346631643666343266653266616165656238326661653330303238222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b317371307739616c706b72303273377063366537337a3068336a723273686a736c7930643734366c756b3233756361337536783271753477646b6a227d
1326	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332362c2268617368223a2233386137356331356635643036393966323033323666636562303464623138613235653063613330356662396566373161616237346338663435313033363961222c22736c6f74223a31333233387d2c22697373756572566b223a2231333065316633353036623739626666383963653632383433363035343639363465663961626338633131383630653938636433613866393830313730653530222c2270726576696f7573426c6f636b223a2236393936613237333666653832363434303538666131643834666135666565363562613032633661613234633335623036363637666435636165343532666166222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3130353370677967346c396336676d6a34636c367632686a366370743930373070786468716635763575647937787379743037677163326a6d7975227d
1327	\\x7b22626f6479223a5b7b22617578696c6961727944617461223a7b225f5f74797065223a22756e646566696e6564227d2c22626f6479223a7b22617578696c696172794461746148617368223a7b225f5f74797065223a22756e646566696e6564227d2c22636572746966696361746573223a5b7b225f5f747970656e616d65223a225374616b654b6579526567697374726174696f6e4365727469666963617465222c227374616b654b657948617368223a226138346261636331306465323230336433303333313235353435396238653137333661323231333463633535346431656435373839613732227d5d2c22636f6c6c61746572616c73223a5b5d2c22666565223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313732393831227d2c22696e70757473223a5b7b22696e646578223a302c2274784964223a2235393663336334613935613061333066636139633833623238646662653933396131643462666430326231666230373866636436383531363137373065363466227d5d2c226d696e74223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c226f757470757473223a5b7b2261646472657373223a22616464725f7465737431717230633366726b656d3963716e35663733646e767170656e6132376b326667716577367763743965616b613033616766776b767a72307a7971376e7176636a32347a65687273687836337a7a64787632347833613474636e666571397a776d6e37222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2233303030303030227d7d7d2c7b2261646472657373223a22616464725f7465737431717230633366726b656d3963716e35663733646e767170656e6132376b326667716577367763743965616b613033616766776b767a72307a7971376e7176636a32347a65687273687836337a7a64787632347833613474636e666571397a776d6e37222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b223632313733623930623536376164346263663235346164306637366562333734643734396430623235666438323738366166366138333961343436663735363236633635343836313665363436633635222c7b225f5f74797065223a22626967696e74222c2276616c7565223a2232227d5d2c5b22363231373362393062353637616434626366323534616430663736656233373464373439643062323566643832373836616636613833396134383635366336633666343836313665363436633635222c7b225f5f74797065223a22626967696e74222c2276616c7565223a2231227d5d2c5b2236323137336239306235363761643462636632353461643066373665623337346437343964306232356664383237383661663661383339613534363537333734343836313665363436633635222c7b225f5f74797065223a22626967696e74222c2276616c7565223a2231227d5d5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2236383237303139227d7d7d5d2c22726571756972656445787472615369676e617475726573223a5b5d2c22736372697074496e7465677269747948617368223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c6964697479496e74657276616c223a7b22696e76616c69644265666f7265223a7b225f5f74797065223a22756e646566696e6564227d2c22696e76616c6964486572656166746572223a31343637387d2c227769746864726177616c73223a5b5d7d2c226964223a2233636432613131323437633464373638343838306336383065613631623235663766626431656462363764383736356565306136636131333063306530623034222c22696e707574536f75726365223a22696e70757473222c227769746e657373223a7b22626f6f747374726170223a5b5d2c22646174756d73223a5b5d2c2272656465656d657273223a5b5d2c2273637269707473223a5b5d2c227369676e617475726573223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b2261323864383864383665633264633963626666373466613030643362363534636330343734396430643165396265303934343762663530386163613330353030222c223163346131663236363032613935663237356633346261343066303166333966346664613236356630316262373333323562363964373563376132353135633864343330303436336138613334363334383538363431306264366565333665643332386362393034653935613065643931633161653736323064373964643030225d5d7d7d7d5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313732393831227d2c22686561646572223a7b22626c6f636b4e6f223a313332372c2268617368223a2262323663383535313532346131363062336636616236303337373230316161636361643365666565653434343831396365636663353266393637646238396166222c22736c6f74223a31333234387d2c22697373756572566b223a2237616235643232623537306434383039306338636265323637396630656261343264376533636634343830366333623134386337303631656338376438653033222c2270726576696f7573426c6f636b223a2233386137356331356635643036393966323033323666636562303464623138613235653063613330356662396566373161616237346338663435313033363961222c2273697a65223a3339372c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2239383237303139227d2c227478436f756e74223a312c22767266223a227672665f766b317371307739616c706b72303273377063366537337a3068336a723273686a736c7930643734366c756b3233756361337536783271753477646b6a227d
1328	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332382c2268617368223a2238383538346439393462363866306538613461613561633162316231303363313464396164643165643734643138653666613639366163623764383234313031222c22736c6f74223a31333235307d2c22697373756572566b223a2234333264636130656533373130613564363634336262333239323464333432633237653966313431383061653335646332376162376163306236346632643539222c2270726576696f7573426c6f636b223a2262323663383535313532346131363062336636616236303337373230316161636361643365666565653434343831396365636663353266393637646238396166222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3134636b346c68306e6637637733666e6e633973727968327a676830646437757a72666a636e63766a636434616a73656767653073677835337175227d
1329	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313332392c2268617368223a2230636365336239396262383165316234393137393034626661306135646335646132633037613834393539366432646233323034616365323761366131616439222c22736c6f74223a31333238387d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2238383538346439393462363866306538613461613561633162316231303363313464396164643165643734643138653666613639366163623764383234313031222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1330	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313333302c2268617368223a2234386231343132396434376562393031616663396433353530316461303430646161666263366166386361323962613965366564373662323331646637306133222c22736c6f74223a31333330307d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2230636365336239396262383165316234393137393034626661306135646335646132633037613834393539366432646233323034616365323761366131616439222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1331	\\x7b22626f6479223a5b7b22617578696c6961727944617461223a7b225f5f74797065223a22756e646566696e6564227d2c22626f6479223a7b22617578696c696172794461746148617368223a7b225f5f74797065223a22756e646566696e6564227d2c22636572746966696361746573223a5b7b225f5f747970656e616d65223a225374616b6544656c65676174696f6e4365727469666963617465222c22706f6f6c4964223a22706f6f6c316d37793267616b7765777179617a303574766d717177766c3268346a6a327178746b6e6b7a6577306468747577757570726571222c227374616b654b657948617368223a226138346261636331306465323230336433303333313235353435396238653137333661323231333463633535346431656435373839613732227d5d2c22636f6c6c61746572616c73223a5b5d2c22666565223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313738373435227d2c22696e70757473223a5b7b22696e646578223a312c2274784964223a2233636432613131323437633464373638343838306336383065613631623235663766626431656462363764383736356565306136636131333063306530623034227d5d2c226d696e74223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c226f757470757473223a5b7b2261646472657373223a22616464725f7465737431717230633366726b656d3963716e35663733646e767170656e6132376b326667716577367763743965616b613033616766776b767a72307a7971376e7176636a32347a65687273687836337a7a64787632347833613474636e666571397a776d6e37222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2233303030303030227d7d7d2c7b2261646472657373223a22616464725f7465737431717230633366726b656d3963716e35663733646e767170656e6132376b326667716577367763743965616b613033616766776b767a72307a7971376e7176636a32347a65687273687836337a7a64787632347833613474636e666571397a776d6e37222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b223632313733623930623536376164346263663235346164306637366562333734643734396430623235666438323738366166366138333961343436663735363236633635343836313665363436633635222c7b225f5f74797065223a22626967696e74222c2276616c7565223a2232227d5d2c5b22363231373362393062353637616434626366323534616430663736656233373464373439643062323566643832373836616636613833396134383635366336633666343836313665363436633635222c7b225f5f74797065223a22626967696e74222c2276616c7565223a2231227d5d2c5b2236323137336239306235363761643462636632353461643066373665623337346437343964306232356664383237383661663661383339613534363537333734343836313665363436633635222c7b225f5f74797065223a22626967696e74222c2276616c7565223a2231227d5d5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2233363438323734227d7d7d5d2c22726571756972656445787472615369676e617475726573223a5b5d2c22736372697074496e7465677269747948617368223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c6964697479496e74657276616c223a7b22696e76616c69644265666f7265223a7b225f5f74797065223a22756e646566696e6564227d2c22696e76616c6964486572656166746572223a31343734307d2c227769746864726177616c73223a5b5d7d2c226964223a2238666663346365326238663933363762356563626537393838393835316639623432616332386333633439613831663464653438633766646439393234623637222c22696e707574536f75726365223a22696e70757473222c227769746e657373223a7b22626f6f747374726170223a5b5d2c22646174756d73223a5b5d2c2272656465656d657273223a5b5d2c2273637269707473223a5b5d2c227369676e617475726573223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b2238343435333239353736633961353736656365373235376266653939333039323766393233396566383736313564363963333137623834316135326137666436222c223432623830376536313532303736643663363136323135663961356637353432333735643963313039376333323739613338623766326563336164363335306331303030313664353662376335643639396531616134616536626464633038623433383230316235663637616434623939626463333962306136353038323034225d2c5b2261323864383864383665633264633963626666373466613030643362363534636330343734396430643165396265303934343762663530386163613330353030222c226462303362303131653834376332363934303637613561633338326234636332386532353562303135653932336539386263353434303635383639623263363264376664653530356137616239373162636537376261346539306239333565643465303331303133623838353235346561373237346665366164353664343035225d5d7d7d7d5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313738373435227d2c22686561646572223a7b22626c6f636b4e6f223a313333312c2268617368223a2263303838353834646465396535303864393234633935323037303164323037383937626438363863653662633066363538346434376561663866336539633131222c22736c6f74223a31333331367d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2234386231343132396434376562393031616663396433353530316461303430646161666263366166386361323962613965366564373662323331646637306133222c2273697a65223a3532382c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2236363438323734227d2c227478436f756e74223a312c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1332	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313333322c2268617368223a2264353066366561383162363739313732336661636535616662646366663235316334383031363663313032646231313738316337646139343565316364313236222c22736c6f74223a31333332397d2c22697373756572566b223a2239373666656661396233333833303634383039633830326232343662353337633131346261633531303766373638646533653630626334303462623339346238222c2270726576696f7573426c6f636b223a2263303838353834646465396535303864393234633935323037303164323037383937626438363863653662633066363538346434376561663866336539633131222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3136776d72367972786b756e6c37636d653673376b6b68656e6d6567646161786b7032336330387472796c6c79796e786b7668707130776b783063227d
1333	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313333332c2268617368223a2238373735303834373333633136326634626330383264343236666166663931373139623233346164396232633366373732356465363737396461306164363565222c22736c6f74223a31333333307d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2264353066366561383162363739313732336661636535616662646366663235316334383031363663313032646231313738316337646139343565316364313236222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1334	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313333342c2268617368223a2236366264393465373937373335396331363535643738396439376165383836343135323861323137353137383535313362303532393037363865643036313431222c22736c6f74223a31333333367d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2238373735303834373333633136326634626330383264343236666166663931373139623233346164396232633366373732356465363737396461306164363565222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1290	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239302c2268617368223a2236323932343362353962626264316234366335646163363838666264303239616538343664333236396535383334313263323338326264316366616230323932222c22736c6f74223a31323930397d2c22697373756572566b223a2231333065316633353036623739626666383963653632383433363035343639363465663961626338633131383630653938636433613866393830313730653530222c2270726576696f7573426c6f636b223a2237643634396331343933633739396565636635376434393632363865306439663535363466623866373431353664336234383533353064353036633837366561222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3130353370677967346c396336676d6a34636c367632686a366370743930373070786468716635763575647937787379743037677163326a6d7975227d
1291	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239312c2268617368223a2266313338663831643936623364353561373563336263323865393862666139313864346461353766376461373863633636663336613338313364373262656631222c22736c6f74223a31323931327d2c22697373756572566b223a2234333264636130656533373130613564363634336262333239323464333432633237653966313431383061653335646332376162376163306236346632643539222c2270726576696f7573426c6f636b223a2236323932343362353962626264316234366335646163363838666264303239616538343664333236396535383334313263323338326264316366616230323932222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3134636b346c68306e6637637733666e6e633973727968327a676830646437757a72666a636e63766a636434616a73656767653073677835337175227d
1292	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239322c2268617368223a2230323438633231323964373831363637653137646639393862343231376230373162623164336234336265373465303834306561613034396238656662346630222c22736c6f74223a31323933307d2c22697373756572566b223a2265383231613831333530386461366561646334343661646165653962376130626462636663376139376161396339636531383462343839636239386166376130222c2270726576696f7573426c6f636b223a2266313338663831643936623364353561373563336263323865393862666139313864346461353766376461373863633636663336613338313364373262656631222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b316c75703538346d7a6a32677873387536367968666a6d7a6837787835716b3430396b6d71683574636d6d3676656d333265756a736d7478706b65227d
1293	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239332c2268617368223a2230303264666264356538316561353465343130633332313033336564656165626565376663343832373034323134303561653339613061393463383838323463222c22736c6f74223a31323933347d2c22697373756572566b223a2239373666656661396233333833303634383039633830326232343662353337633131346261633531303766373638646533653630626334303462623339346238222c2270726576696f7573426c6f636b223a2230323438633231323964373831363637653137646639393862343231376230373162623164336234336265373465303834306561613034396238656662346630222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3136776d72367972786b756e6c37636d653673376b6b68656e6d6567646161786b7032336330387472796c6c79796e786b7668707130776b783063227d
1294	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239342c2268617368223a2235306537363333343965383164363032396432376265356664616634356631613137373365366662393931646430356363653034353162323030336466633161222c22736c6f74223a31323934307d2c22697373756572566b223a2231333065316633353036623739626666383963653632383433363035343639363465663961626338633131383630653938636433613866393830313730653530222c2270726576696f7573426c6f636b223a2230303264666264356538316561353465343130633332313033336564656165626565376663343832373034323134303561653339613061393463383838323463222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3130353370677967346c396336676d6a34636c367632686a366370743930373070786468716635763575647937787379743037677163326a6d7975227d
1295	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239352c2268617368223a2230313130396534666532643765633836303966613230383563613465306261326632396332623133393833653236616130643631353930633065623232303235222c22736c6f74223a31323934357d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2235306537363333343965383164363032396432376265356664616634356631613137373365366662393931646430356363653034353162323030336466633161222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1296	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239362c2268617368223a2233313537326266383964393264643364373564303339636464663036373363393662623534313934376636333537316263653439623363323537383364366261222c22736c6f74223a31323934377d2c22697373756572566b223a2263393534376665666362323631363533643565396431326463616333383234323962356139306463306537636331633936313333393931366137646335643238222c2270726576696f7573426c6f636b223a2230313130396534666532643765633836303966613230383563613465306261326632396332623133393833653236616130643631353930633065623232303235222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31386771396e6630687468393539346573366e637361617a746474377977386d66616d75736b6b306a646875726e6b7170386a6671737737767779227d
1297	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239372c2268617368223a2238393931303831303466663835303531666365373836333433363265336264613831643737333733656131343962346333396361316563636239363631376132222c22736c6f74223a31323934397d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2233313537326266383964393264643364373564303339636464663036373363393662623534313934376636333537316263653439623363323537383364366261222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1298	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239382c2268617368223a2236393831353335346535633034333964336634666361393334313033356437336632613835633337626338623630366130343138373835346664346434373635222c22736c6f74223a31323935317d2c22697373756572566b223a2263363032313464323738383530616636663866393738353761336532343039353337633235613636323535363331373832313966336431366531636365313631222c2270726576696f7573426c6f636b223a2238393931303831303466663835303531666365373836333433363265336264613831643737333733656131343962346333396361316563636239363631376132222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31777a76346d7961786c35676a6170717666746a636364783374636c70307039687972356b6c756c6e363377397961327570326371706379796779227d
1299	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313239392c2268617368223a2236356162376362326330366636326532653332663631303737343161343134363266306135346532396635346237366530316164336131393936656237633635222c22736c6f74223a31323935367d2c22697373756572566b223a2233613039306333333430346437633663353733613436636138393061363039653265653865623938663932626437393331323335323666313565616636666465222c2270726576696f7573426c6f636b223a2236393831353335346535633034333964336634666361393334313033356437336632613835633337626338623630366130343138373835346664346434373635222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31716c36766b7a7a7078346a33746a6b386d3638746871387767743366657a7a766d3461666573726e6170326433346538653764736c6672777479227d
1300	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330302c2268617368223a2265356132656633303031333631393238383435376133363632623965313831373737346364363733356161363831666535643137356237396466643934306139222c22736c6f74223a31323935397d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2236356162376362326330366636326532653332663631303737343161343134363266306135346532396635346237366530316164336131393936656237633635222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1301	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330312c2268617368223a2238656634383261386661613361303039306232373334663631346336636333613636636531336364383163666562633938383264306165393564633464306263222c22736c6f74223a31323937307d2c22697373756572566b223a2234333264636130656533373130613564363634336262333239323464333432633237653966313431383061653335646332376162376163306236346632643539222c2270726576696f7573426c6f636b223a2265356132656633303031333631393238383435376133363632623965313831373737346364363733356161363831666535643137356237396466643934306139222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b3134636b346c68306e6637637733666e6e633973727968327a676830646437757a72666a636e63766a636434616a73656767653073677835337175227d
1302	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330322c2268617368223a2236653638316439613464363665303432303731313733653733336163626237326561616563303062386263643937393566623364323932346561313132323139222c22736c6f74223a31323939317d2c22697373756572566b223a2265383231613831333530386461366561646334343661646165653962376130626462636663376139376161396339636531383462343839636239386166376130222c2270726576696f7573426c6f636b223a2238656634383261386661613361303039306232373334663631346336636333613636636531336364383163666562633938383264306165393564633464306263222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b316c75703538346d7a6a32677873387536367968666a6d7a6837787835716b3430396b6d71683574636d6d3676656d333265756a736d7478706b65227d
1303	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330332c2268617368223a2239346163636333323464313462636463386136343131616238356533363864356332303030363564396431653838636635623233653565643534363830663333222c22736c6f74223a31333032317d2c22697373756572566b223a2263393534376665666362323631363533643565396431326463616333383234323962356139306463306537636331633936313333393931366137646335643238222c2270726576696f7573426c6f636b223a2236653638316439613464363665303432303731313733653733336163626237326561616563303062386263643937393566623364323932346561313132323139222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31386771396e6630687468393539346573366e637361617a746474377977386d66616d75736b6b306a646875726e6b7170386a6671737737767779227d
1304	\\x7b22626f6479223a5b7b22617578696c6961727944617461223a7b225f5f74797065223a22756e646566696e6564227d2c22626f6479223a7b22617578696c696172794461746148617368223a7b225f5f74797065223a22756e646566696e6564227d2c22636572746966696361746573223a5b5d2c22636f6c6c61746572616c73223a5b5d2c22666565223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313830393031227d2c22696e70757473223a5b7b22696e646578223a302c2274784964223a2234326634613133336630343462306239616461333237623266643633366266383434323933306639313531343264656539326565363838623234306266343965227d5d2c226d696e74223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c226f757470757473223a5b7b2261646472657373223a22616464725f746573743171707730646a676a307835396e67726a767174686e37656e68767275786e736176737735746836336c61336d6a656c33746b63393734737232336a6d6c7a6771357a646134677476386b39637933383735367239793371676d6b71716a7a36616137222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2235303030303030227d7d7d2c7b2261646472657373223a22616464725f746573743171707730646a676a307835396e67726a767174686e37656e68767275786e736176737735746836336c61336d6a656c33746b63393734737232336a6d6c7a6771357a646134677476386b39637933383735367239793371676d6b71716a7a36616137222c22646174756d223a7b225f5f74797065223a22756e646566696e6564227d2c22646174756d48617368223a7b225f5f74797065223a22756e646566696e6564227d2c227363726970745265666572656e6365223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c7565223a7b22617373657473223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5d7d2c22636f696e73223a7b225f5f74797065223a22626967696e74222c2276616c7565223a223136333335343933393731227d7d7d5d2c22726571756972656445787472615369676e617475726573223a5b5d2c22736372697074496e7465677269747948617368223a7b225f5f74797065223a22756e646566696e6564227d2c2276616c6964697479496e74657276616c223a7b22696e76616c69644265666f7265223a7b225f5f74797065223a22756e646566696e6564227d2c22696e76616c6964486572656166746572223a31343436317d2c227769746864726177616c73223a5b7b227175616e74697479223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2234373739323634363734227d2c227374616b6541646472657373223a227374616b655f7465737431757263716a65663432657579637733376d75703532346d66346a3577716c77796c77776d39777a6a70347634326b736a6773676379227d2c7b227175616e74697479223a7b225f5f74797065223a22626967696e74222c2276616c7565223a223131353536343130313938227d2c227374616b6541646472657373223a227374616b655f7465737431757263346d767a6c326370346765646c337971327078373635396b726d7a757a676e6c3264706a6a677379646d71717867616d6a37227d5d7d2c226964223a2235383233613637633533643335326538336662623936333739373837356635376233313039643264303333313935616562383866626162653733666565353730222c22696e707574536f75726365223a22696e70757473222c227769746e657373223a7b22626f6f747374726170223a5b5d2c22646174756d73223a5b5d2c2272656465656d657273223a5b5d2c2273637269707473223a5b5d2c227369676e617475726573223a7b225f5f74797065223a224d6170222c2276616c7565223a5b5b2233363863663661313161633765323939313735363861333636616636326135393663623963646538313734626665376636653838333933656364623164636336222c223136393964396538393738323336613036303661623562356330633336356432343032646265646531613565643961363463646139653136656331653732323664643063663338633761633961306161613930303265383663343930393665366266626164613661303132623338313563353238326432653339343733323062225d2c5b2238373563316539386262626265396337376264646364373063613464373261633964303734303837346561643161663932393036323936353533663866333433222c223363323361316436323339393566363935343730373630396466343237653532393635376561313739643835303433313636326139393230643338666263363966306530396539323731376461636639346432343438326332343639623338383966366333373431626366666462616464313566343464623336616431323065225d2c5b2238363439393462663364643637393466646635366233623264343034363130313038396436643038393164346130616132343333316566383662306162386261222c223466303763386538326263623039373033393631353034343635353033663630343135653430323662623634313862333433313761376335383436313633653362383332373032363738373164353666333433313230353138313337633864363734623335373034383536656237613037373031363734653063376337333037225d5d7d7d7d5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a22313830393031227d2c22686561646572223a7b22626c6f636b4e6f223a313330342c2268617368223a2264363339373930363264663062303339636265643165376437346266303561636537636136313938623264613264313432316232366666313261386239383035222c22736c6f74223a31333033357d2c22697373756572566b223a2262336136636336653830356236623866366432316163386130666537326231336234373539373737653431363663336538333235666563303935643737303937222c2270726576696f7573426c6f636b223a2239346163636333323464313462636463386136343131616238356533363864356332303030363564396431653838636635623233653565643534363830663333222c2273697a65223a3537372c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a223136333430343933393731227d2c227478436f756e74223a312c22767266223a227672665f766b31396b61787164707570637a34676b66353672733464777566347a6e3433373678667561306b7676303975663976343364396e68736e706d746165227d
1305	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330352c2268617368223a2261386237316332663033633464653331326562333661393730316566653731373433383961343633386462376232383165613163306465656337636332636166222c22736c6f74223a31333035327d2c22697373756572566b223a2237616235643232623537306434383039306338636265323637396630656261343264376533636634343830366333623134386337303631656338376438653033222c2270726576696f7573426c6f636b223a2264363339373930363264663062303339636265643165376437346266303561636537636136313938623264613264313432316232366666313261386239383035222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b317371307739616c706b72303273377063366537337a3068336a723273686a736c7930643734366c756b3233756361337536783271753477646b6a227d
1306	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330362c2268617368223a2266316463313136346131346631653263303638623833643964646337663433643434333563383230326233386164633630393536316536346331326636343966222c22736c6f74223a31333035337d2c22697373756572566b223a2233613039306333333430346437633663353733613436636138393061363039653265653865623938663932626437393331323335323666313565616636666465222c2270726576696f7573426c6f636b223a2261386237316332663033633464653331326562333661393730316566653731373433383961343633386462376232383165613163306465656337636332636166222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b31716c36766b7a7a7078346a33746a6b386d3638746871387767743366657a7a766d3461666573726e6170326433346538653764736c6672777479227d
1307	\\x7b22626f6479223a5b5d2c2266656573223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c22686561646572223a7b22626c6f636b4e6f223a313330372c2268617368223a2239643166313262643365653664643066626436323238363264303838643062376462353862376234636639366636396362623731313331323963643063386534222c22736c6f74223a31333035367d2c22697373756572566b223a2265383231613831333530386461366561646334343661646165653962376130626462636663376139376161396339636531383462343839636239386166376130222c2270726576696f7573426c6f636b223a2266316463313136346131346631653263303638623833643964646337663433643434333563383230326233386164633630393536316536346331326636343966222c2273697a65223a342c22746f74616c4f7574707574223a7b225f5f74797065223a22626967696e74222c2276616c7565223a2230227d2c227478436f756e74223a302c22767266223a227672665f766b316c75703538346d7a6a32677873387536367968666a6d7a6837787835716b3430396b6d71683574636d6d3676656d333265756a736d7478706b65227d
\.


--
-- Data for Name: current_pool_metrics; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.current_pool_metrics (stake_pool_id, slot, minted_blocks, live_delegators, active_stake, live_stake, live_pledge, live_saturation, active_size, live_size, apy) FROM stdin;
pool1l9vraj8qf0042n5j8snl3u5lg8vlfzt0zczdw6wlzv3g7ldvlw3	10066	100	2	3704549039202255	3704549039202255	300000000	4.505127838358728	1	0	0
pool13fpyflv8uw83sxg4sdpj36g7fm3qds2z93rnlcatna887f4lhdm	10066	92	2	3729578166623905	3735665874484544	500000000	4.542969238050943	0.9983703821312769	0.0016296178687230656	0
pool1fljeydsfvwejj60ns72j853ygf3vtxae9ry8ppuzgdxkw9x3mm5	10066	113	2	3742651001823043	3751769472803271	8416410138313	4.562552935908824	0.9975695545671641	0.0024304454328358815	0
pool19f5g767d4j3gljwaxzg256cx24e5kdwmgsqmsfv06f6dvt3vs0m	10066	101	2	3728138218480075	3737275294959608	5844578261748	4.544926465478386	0.9975551502743574	0.0024448497256426283	0
pool1h5hgjazd5mjpyl26708ag7en4we38cjzuv27w9c7nxgvvl2emyc	10066	91	2	3695795611825290	3695795611825290	200375813	4.494482734477066	1	0	0
pool1d9pmphwkkezcdha48qzjg6fr784xaq9yad2llj0hwcrp7ldnufq	10066	100	3	3738906939992448	3746275815798478	6549873111781	4.555872061436714	0.9980330130058885	0.0019669869941114637	0
pool1svasg66clvn2rf0phz2yrtcphk4cgpecjseqmck562w22xa578g	10066	81	2	3722955652147938	3728444596952154	5173795456905	4.534187392245848	0.9985278191316822	0.0014721808683177962	0
pool1tzrwtvn8ssr3ap90suzuk9rplv47v7hxusmfndrrrhsvc3u03gl	10066	97	2	3727987477240537	3735301913514329	5810491421700	4.542526622585028	0.9980418085490417	0.0019581914509583243	0
pool1xyd8d2jr3qac25f4lzzmq4aunyzqct08p275s7f3zvplyx5mz3t	10066	96	8	3742790219609164	3748181355132155	6971011754837	4.5581894010665565	0.9985616663090197	0.0014383336909803424	0
pool1cxm9yp2w3tg7mvegfsu9d7fdt200tf4s0303krcrj4whjxne52w	10066	78	2	0	3697542865234202	300000000	4.496607581493493	0	1	0
pool19qxvm4eu4m2ucaqcx2w6p08d7sy2ljta895qnve2m53hcc4nsgy	10066	53	2	0	3720658938711102	500000000	4.524719199137717	0	1	0
\.


--
-- Data for Name: pool_metadata; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.pool_metadata (id, ticker, name, description, homepage, hash, ext, stake_pool_id, pool_update_id) FROM stdin;
1	SP3	Stake Pool - 3	This is the stake pool 3 description.	https://stakepool3.com	6d3ce01216ac833311cbb44c6793325bc14f12d559a83b2237f60eeb66e85f25	\N	pool1h5hgjazd5mjpyl26708ag7en4we38cjzuv27w9c7nxgvvl2emyc	2810000000000
2	SP1	stake pool - 1	This is the stake pool 1 description.	https://stakepool1.com	14ea470ac1deb37c5d5f2674cfee849d40fa0fe5265fccc78f2fdb4cec73dfc7	\N	pool1fljeydsfvwejj60ns72j853ygf3vtxae9ry8ppuzgdxkw9x3mm5	820000000000
3	SP5	Same Name	This is the stake pool 5 description.	https://stakepool5.com	0f118a34e20bd77f8a9ba5e27481eba54d063630c4c1c017bad11a2fba615501	\N	pool1svasg66clvn2rf0phz2yrtcphk4cgpecjseqmck562w22xa578g	4620000000000
4	SP4	Same Name	This is the stake pool 4 description.	https://stakepool4.com	09dd809e0fecfc0ef01e3bc225d54a60b4de3eed39a8574a9e350d2ec952dc8d	\N	pool1d9pmphwkkezcdha48qzjg6fr784xaq9yad2llj0hwcrp7ldnufq	3960000000000
5	SP6a7	Stake Pool - 6	This is the stake pool 6 description.	https://stakepool6.com	3806b0c100c6019d0ed25233ad823a1c505fd6bd05aad617be09d420082914ba	\N	pool1tzrwtvn8ssr3ap90suzuk9rplv47v7hxusmfndrrrhsvc3u03gl	5790000000000
6	SP6a7		This is the stake pool 7 description.	https://stakepool7.com	c431584ed48f8ce7dda609659a4905e90bf7ca95e4f8b4fddb7e05ce4315d405	\N	pool1xyd8d2jr3qac25f4lzzmq4aunyzqct08p275s7f3zvplyx5mz3t	6750000000000
7	SP10	Stake Pool - 10	This is the stake pool 10 description.	https://stakepool10.com	c054facebb7063a319711b4d680a4c513005663a1d47e8e8a41a4cef45812ffd	\N	pool19qxvm4eu4m2ucaqcx2w6p08d7sy2ljta895qnve2m53hcc4nsgy	9890000000000
8	SP11	Stake Pool - 10 + 1	This is the stake pool 11 description.	https://stakepool11.com	4c1c15c4b9fd85a94b5d89e1031db403dd65da928289c40fa2513165b77dcdc9	\N	pool13fpyflv8uw83sxg4sdpj36g7fm3qds2z93rnlcatna887f4lhdm	11170000000000
\.


--
-- Data for Name: pool_registration; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.pool_registration (id, reward_account, pledge, cost, margin, margin_percent, relays, owners, vrf, metadata_url, metadata_hash, stake_pool_id, block_slot) FROM stdin;
820000000000	stake_test1uprlhvrwxj8venllwsjpq9mu629q0ptt7svuqsapr90w7dcsq97ms	400000000	390000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3001, "__typename": "RelayByAddress"}]	["stake_test1uprlhvrwxj8venllwsjpq9mu629q0ptt7svuqsapr90w7dcsq97ms"]	927b448ee9d4a15a5ea11c4de48ee552fa3e371c0a19c01e45d28e6f6212426e	http://file-server/SP1.json	14ea470ac1deb37c5d5f2674cfee849d40fa0fe5265fccc78f2fdb4cec73dfc7	pool1fljeydsfvwejj60ns72j853ygf3vtxae9ry8ppuzgdxkw9x3mm5	82
1810000000000	stake_test1uq0ekznmqpy8aq7x8tusaq0yuvj9vqq7ru7twuwp6mqqnjgdcrhtd	500000000	390000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3002, "__typename": "RelayByAddress"}]	["stake_test1uq0ekznmqpy8aq7x8tusaq0yuvj9vqq7ru7twuwp6mqqnjgdcrhtd"]	265b7e85d737edaa1eeb3effa3b8d994f26ae22e7b21fb1e2bbf3ecb36bc566c	\N	\N	pool19f5g767d4j3gljwaxzg256cx24e5kdwmgsqmsfv06f6dvt3vs0m	181
2810000000000	stake_test1uqtzlf2cppsk2a7g7jtjstuchw056wwe43g8yp69sm8fa5gdytksp	600000000	390000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3003, "__typename": "RelayByAddress"}]	["stake_test1uqtzlf2cppsk2a7g7jtjstuchw056wwe43g8yp69sm8fa5gdytksp"]	c5fba6a50bf972c8c73e871817a87d0a7d4dd7cfb299b041c9f98a0fd719f128	http://file-server/SP3.json	6d3ce01216ac833311cbb44c6793325bc14f12d559a83b2237f60eeb66e85f25	pool1h5hgjazd5mjpyl26708ag7en4we38cjzuv27w9c7nxgvvl2emyc	281
3960000000000	stake_test1uqkxwjher6ptz5wey6szkprc2wmq07fkg7ahmq5uzsm9pfqmrs64k	420000000	370000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3004, "__typename": "RelayByAddress"}]	["stake_test1uqkxwjher6ptz5wey6szkprc2wmq07fkg7ahmq5uzsm9pfqmrs64k"]	0e5ca4c18e299b8eb7e99982058adb1e190e08cbf4e61440b3c3d87ecb8d3492	http://file-server/SP4.json	09dd809e0fecfc0ef01e3bc225d54a60b4de3eed39a8574a9e350d2ec952dc8d	pool1d9pmphwkkezcdha48qzjg6fr784xaq9yad2llj0hwcrp7ldnufq	396
4620000000000	stake_test1upeg0yxs49hdsrgemjrysfgjdc0af4vjn96664zhy250nwcd5gtkg	410000000	390000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3005, "__typename": "RelayByAddress"}]	["stake_test1upeg0yxs49hdsrgemjrysfgjdc0af4vjn96664zhy250nwcd5gtkg"]	0e39cf5cf296d28a333861798e5865b9794b42796d91bc31ef6297d2d8ff2a00	http://file-server/SP5.json	0f118a34e20bd77f8a9ba5e27481eba54d063630c4c1c017bad11a2fba615501	pool1svasg66clvn2rf0phz2yrtcphk4cgpecjseqmck562w22xa578g	462
5790000000000	stake_test1uzxdp7azcdhlxk3qrfra3nslnz7q5963d0h48x75ysdjtfs79jugv	410000000	400000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3006, "__typename": "RelayByAddress"}]	["stake_test1uzxdp7azcdhlxk3qrfra3nslnz7q5963d0h48x75ysdjtfs79jugv"]	cc8b277cda6cc09005c45e06fbaafe68fac865adfd622858cb47b2446d787e98	http://file-server/SP6.json	3806b0c100c6019d0ed25233ad823a1c505fd6bd05aad617be09d420082914ba	pool1tzrwtvn8ssr3ap90suzuk9rplv47v7hxusmfndrrrhsvc3u03gl	579
6750000000000	stake_test1uqhau4cwcxvxw02w5s3gaez0g23gaer9c0qxh7nu9p4fc7q5n53vm	410000000	390000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3007, "__typename": "RelayByAddress"}]	["stake_test1uqhau4cwcxvxw02w5s3gaez0g23gaer9c0qxh7nu9p4fc7q5n53vm"]	05ace6cbd31b5fba7aae0fbe418a1faa2243cdd8fe719447c2bb3dd6c7b2ef82	http://file-server/SP7.json	c431584ed48f8ce7dda609659a4905e90bf7ca95e4f8b4fddb7e05ce4315d405	pool1xyd8d2jr3qac25f4lzzmq4aunyzqct08p275s7f3zvplyx5mz3t	675
7890000000000	stake_test1uzmwqnftm6hmyvskdx8zqyvedhyupkqttzkn9npjyuqptlqmd4k6s	500000000	380000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3008, "__typename": "RelayByAddress"}]	["stake_test1uzmwqnftm6hmyvskdx8zqyvedhyupkqttzkn9npjyuqptlqmd4k6s"]	2a54c79aaced460f8da56dcf23283b5aeab2e37d4280bff6f69cf844a8406c5b	\N	\N	pool1cxm9yp2w3tg7mvegfsu9d7fdt200tf4s0303krcrj4whjxne52w	789
8820000000000	stake_test1uqvqpy8as0p39ergz362jes7smdc48z69rwsvvtvceapvsqflc0px	500000000	390000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 3009, "__typename": "RelayByAddress"}]	["stake_test1uqvqpy8as0p39ergz362jes7smdc48z69rwsvvtvceapvsqflc0px"]	3b3187802eff459730a6ed16b8f74f3b9492c3299b52898df1e0fc777021c285	\N	\N	pool1l9vraj8qf0042n5j8snl3u5lg8vlfzt0zczdw6wlzv3g7ldvlw3	882
9890000000000	stake_test1uzwjy0tad5p2hrr2yyfayrve6kch2a62cwhx46efqwf70tqghhfgl	400000000	410000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 30010, "__typename": "RelayByAddress"}]	["stake_test1uzwjy0tad5p2hrr2yyfayrve6kch2a62cwhx46efqwf70tqghhfgl"]	b825aeca0448833d242faa4c7dccd80ed7975dc8a6313492d4ed8d8cc9d92514	http://file-server/SP10.json	c054facebb7063a319711b4d680a4c513005663a1d47e8e8a41a4cef45812ffd	pool19qxvm4eu4m2ucaqcx2w6p08d7sy2ljta895qnve2m53hcc4nsgy	989
11170000000000	stake_test1uqx67w4qn66zhj796j9z2jamrlv5elgzz9k2jmsyfu5rghq7mpet7	400000000	390000000	{"numerator": 3, "denominator": 20}	0.150000006	[{"ipv4": "127.0.0.1", "port": 30011, "__typename": "RelayByAddress"}]	["stake_test1uqx67w4qn66zhj796j9z2jamrlv5elgzz9k2jmsyfu5rghq7mpet7"]	5b586190b171b79c86d744ea82029968461292ca14ef94a1a2270eeedbed4bb5	http://file-server/SP11.json	4c1c15c4b9fd85a94b5d89e1031db403dd65da928289c40fa2513165b77dcdc9	pool13fpyflv8uw83sxg4sdpj36g7fm3qds2z93rnlcatna887f4lhdm	1117
131180000000000	stake_test1urstxrwzzu6mxs38c0pa0fpnse0jsdv3d4fyy92lzzsg3qssvrwys	500000000000000	1000	{"numerator": 1, "denominator": 5}	0.200000003	[{"ipv4": "127.0.0.1", "port": 6000, "__typename": "RelayByAddress"}]	["stake_test1urstxrwzzu6mxs38c0pa0fpnse0jsdv3d4fyy92lzzsg3qssvrwys"]	2ee5a4c423224bb9c42107fc18a60556d6a83cec1d9dd37a71f56af7198fc759	\N	\N	pool1e4eq6j07vld0wu9qwpjk5mey426cwuszj7lxv89tht3u6t8nvg4	13118
132290000000000	stake_test1uz5yhtxpph3zq0fsxvf923vm3ctndg3pxnx92ng764uf5usnqkg5v	50000000	1000	{"numerator": 1, "denominator": 5}	0.200000003	[{"ipv4": "127.0.0.2", "port": 6000, "__typename": "RelayByAddress"}]	["stake_test1uz5yhtxpph3zq0fsxvf923vm3ctndg3pxnx92ng764uf5usnqkg5v"]	641d042ed39c2c258d381060c1424f40ef8abfe25ef566f4cb22477c42b2a014	\N	\N	pool1m7y2gakwewqyaz05tvmqqwvl2h4jj2qxtknkzew0dhtuwuupreq	13229
\.


--
-- Data for Name: pool_retirement; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.pool_retirement (id, retire_at_epoch, stake_pool_id, block_slot) FROM stdin;
8160000000000	5	pool1cxm9yp2w3tg7mvegfsu9d7fdt200tf4s0303krcrj4whjxne52w	816
9100000000000	18	pool1l9vraj8qf0042n5j8snl3u5lg8vlfzt0zczdw6wlzv3g7ldvlw3	910
10400000000000	5	pool19qxvm4eu4m2ucaqcx2w6p08d7sy2ljta895qnve2m53hcc4nsgy	1040
11430000000000	18	pool13fpyflv8uw83sxg4sdpj36g7fm3qds2z93rnlcatna887f4lhdm	1143
\.


--
-- Data for Name: stake_pool; Type: TABLE DATA; Schema: public; Owner: postgres
--

COPY public.stake_pool (id, status, last_registration_id, last_retirement_id) FROM stdin;
pool1l9vraj8qf0042n5j8snl3u5lg8vlfzt0zczdw6wlzv3g7ldvlw3	retiring	8820000000000	9100000000000
pool13fpyflv8uw83sxg4sdpj36g7fm3qds2z93rnlcatna887f4lhdm	retiring	11170000000000	11430000000000
pool1fljeydsfvwejj60ns72j853ygf3vtxae9ry8ppuzgdxkw9x3mm5	active	820000000000	\N
pool19f5g767d4j3gljwaxzg256cx24e5kdwmgsqmsfv06f6dvt3vs0m	active	1810000000000	\N
pool1h5hgjazd5mjpyl26708ag7en4we38cjzuv27w9c7nxgvvl2emyc	active	2810000000000	\N
pool1d9pmphwkkezcdha48qzjg6fr784xaq9yad2llj0hwcrp7ldnufq	active	3960000000000	\N
pool1svasg66clvn2rf0phz2yrtcphk4cgpecjseqmck562w22xa578g	active	4620000000000	\N
pool1tzrwtvn8ssr3ap90suzuk9rplv47v7hxusmfndrrrhsvc3u03gl	active	5790000000000	\N
pool1xyd8d2jr3qac25f4lzzmq4aunyzqct08p275s7f3zvplyx5mz3t	active	6750000000000	\N
pool1cxm9yp2w3tg7mvegfsu9d7fdt200tf4s0303krcrj4whjxne52w	retired	7890000000000	8160000000000
pool19qxvm4eu4m2ucaqcx2w6p08d7sy2ljta895qnve2m53hcc4nsgy	retired	9890000000000	10400000000000
pool1e4eq6j07vld0wu9qwpjk5mey426cwuszj7lxv89tht3u6t8nvg4	activating	131180000000000	\N
pool1m7y2gakwewqyaz05tvmqqwvl2h4jj2qxtknkzew0dhtuwuupreq	activating	132290000000000	\N
\.


--
-- Name: pool_metadata_id_seq; Type: SEQUENCE SET; Schema: public; Owner: postgres
--

SELECT pg_catalog.setval('public.pool_metadata_id_seq', 8, true);


--
-- Name: job job_pkey; Type: CONSTRAINT; Schema: pgboss; Owner: postgres
--

ALTER TABLE ONLY pgboss.job
    ADD CONSTRAINT job_pkey PRIMARY KEY (id);


--
-- Name: schedule schedule_pkey; Type: CONSTRAINT; Schema: pgboss; Owner: postgres
--

ALTER TABLE ONLY pgboss.schedule
    ADD CONSTRAINT schedule_pkey PRIMARY KEY (name);


--
-- Name: subscription subscription_pkey; Type: CONSTRAINT; Schema: pgboss; Owner: postgres
--

ALTER TABLE ONLY pgboss.subscription
    ADD CONSTRAINT subscription_pkey PRIMARY KEY (event, name);


--
-- Name: version version_pkey; Type: CONSTRAINT; Schema: pgboss; Owner: postgres
--

ALTER TABLE ONLY pgboss.version
    ADD CONSTRAINT version_pkey PRIMARY KEY (version);


--
-- Name: block_data PK_block_data_block_height; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.block_data
    ADD CONSTRAINT "PK_block_data_block_height" PRIMARY KEY (block_height);


--
-- Name: block PK_block_slot; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.block
    ADD CONSTRAINT "PK_block_slot" PRIMARY KEY (slot);


--
-- Name: current_pool_metrics PK_current_pool_metrics_stake_pool_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.current_pool_metrics
    ADD CONSTRAINT "PK_current_pool_metrics_stake_pool_id" PRIMARY KEY (stake_pool_id);


--
-- Name: pool_metadata PK_pool_metadata_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_metadata
    ADD CONSTRAINT "PK_pool_metadata_id" PRIMARY KEY (id);


--
-- Name: pool_registration PK_pool_registration_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_registration
    ADD CONSTRAINT "PK_pool_registration_id" PRIMARY KEY (id);


--
-- Name: pool_retirement PK_pool_retirement_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_retirement
    ADD CONSTRAINT "PK_pool_retirement_id" PRIMARY KEY (id);


--
-- Name: stake_pool PK_stake_pool_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.stake_pool
    ADD CONSTRAINT "PK_stake_pool_id" PRIMARY KEY (id);


--
-- Name: pool_metadata REL_pool_metadata_pool_update_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_metadata
    ADD CONSTRAINT "REL_pool_metadata_pool_update_id" UNIQUE (pool_update_id);


--
-- Name: stake_pool REL_stake_pool_last_registration_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.stake_pool
    ADD CONSTRAINT "REL_stake_pool_last_registration_id" UNIQUE (last_registration_id);


--
-- Name: stake_pool REL_stake_pool_last_retirement_id; Type: CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.stake_pool
    ADD CONSTRAINT "REL_stake_pool_last_retirement_id" UNIQUE (last_retirement_id);


--
-- Name: archive_archivedon_idx; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE INDEX archive_archivedon_idx ON pgboss.archive USING btree (archivedon);


--
-- Name: archive_id_idx; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE INDEX archive_id_idx ON pgboss.archive USING btree (id);


--
-- Name: job_fetch; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE INDEX job_fetch ON pgboss.job USING btree (name text_pattern_ops, startafter) WHERE (state < 'active'::pgboss.job_state);


--
-- Name: job_name; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE INDEX job_name ON pgboss.job USING btree (name text_pattern_ops);


--
-- Name: job_singleton_queue; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE UNIQUE INDEX job_singleton_queue ON pgboss.job USING btree (name, singletonkey) WHERE ((state < 'active'::pgboss.job_state) AND (singletonon IS NULL) AND (singletonkey ~~ '\_\_pgboss\_\_singleton\_queue%'::text));


--
-- Name: job_singletonkey; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE UNIQUE INDEX job_singletonkey ON pgboss.job USING btree (name, singletonkey) WHERE ((state < 'completed'::pgboss.job_state) AND (singletonon IS NULL) AND (NOT (singletonkey ~~ '\_\_pgboss\_\_singleton\_queue%'::text)));


--
-- Name: job_singletonkeyon; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE UNIQUE INDEX job_singletonkeyon ON pgboss.job USING btree (name, singletonon, singletonkey) WHERE (state < 'expired'::pgboss.job_state);


--
-- Name: job_singletonon; Type: INDEX; Schema: pgboss; Owner: postgres
--

CREATE UNIQUE INDEX job_singletonon ON pgboss.job USING btree (name, singletonon) WHERE ((state < 'expired'::pgboss.job_state) AND (singletonkey IS NULL));


--
-- Name: IDX_block_hash; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX "IDX_block_hash" ON public.block USING btree (hash);


--
-- Name: IDX_block_height; Type: INDEX; Schema: public; Owner: postgres
--

CREATE UNIQUE INDEX "IDX_block_height" ON public.block USING btree (height);


--
-- Name: IDX_pool_metadata_name; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX "IDX_pool_metadata_name" ON public.pool_metadata USING btree (name);


--
-- Name: IDX_pool_metadata_ticker; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX "IDX_pool_metadata_ticker" ON public.pool_metadata USING btree (ticker);


--
-- Name: IDX_stake_pool_status; Type: INDEX; Schema: public; Owner: postgres
--

CREATE INDEX "IDX_stake_pool_status" ON public.stake_pool USING btree (status);


--
-- Name: job job_block_slot_fkey; Type: FK CONSTRAINT; Schema: pgboss; Owner: postgres
--

ALTER TABLE ONLY pgboss.job
    ADD CONSTRAINT job_block_slot_fkey FOREIGN KEY (block_slot) REFERENCES public.block(slot) ON DELETE CASCADE;


--
-- Name: block_data FK_block_data_block_height; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.block_data
    ADD CONSTRAINT "FK_block_data_block_height" FOREIGN KEY (block_height) REFERENCES public.block(height) ON DELETE CASCADE;


--
-- Name: current_pool_metrics FK_current_pool_metrics_stake_pool_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.current_pool_metrics
    ADD CONSTRAINT "FK_current_pool_metrics_stake_pool_id" FOREIGN KEY (stake_pool_id) REFERENCES public.stake_pool(id) ON DELETE CASCADE;


--
-- Name: pool_metadata FK_pool_metadata_pool_update_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_metadata
    ADD CONSTRAINT "FK_pool_metadata_pool_update_id" FOREIGN KEY (pool_update_id) REFERENCES public.pool_registration(id) ON DELETE CASCADE;


--
-- Name: pool_metadata FK_pool_metadata_stake_pool_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_metadata
    ADD CONSTRAINT "FK_pool_metadata_stake_pool_id" FOREIGN KEY (stake_pool_id) REFERENCES public.stake_pool(id);


--
-- Name: pool_registration FK_pool_registration_block_slot; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_registration
    ADD CONSTRAINT "FK_pool_registration_block_slot" FOREIGN KEY (block_slot) REFERENCES public.block(slot) ON DELETE CASCADE;


--
-- Name: pool_registration FK_pool_registration_stake_pool_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_registration
    ADD CONSTRAINT "FK_pool_registration_stake_pool_id" FOREIGN KEY (stake_pool_id) REFERENCES public.stake_pool(id) ON DELETE CASCADE;


--
-- Name: pool_retirement FK_pool_retirement_block_slot; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_retirement
    ADD CONSTRAINT "FK_pool_retirement_block_slot" FOREIGN KEY (block_slot) REFERENCES public.block(slot) ON DELETE CASCADE;


--
-- Name: pool_retirement FK_pool_retirement_stake_pool_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.pool_retirement
    ADD CONSTRAINT "FK_pool_retirement_stake_pool_id" FOREIGN KEY (stake_pool_id) REFERENCES public.stake_pool(id) ON DELETE CASCADE;


--
-- Name: stake_pool FK_stake_pool_last_registration_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.stake_pool
    ADD CONSTRAINT "FK_stake_pool_last_registration_id" FOREIGN KEY (last_registration_id) REFERENCES public.pool_registration(id) ON DELETE SET NULL;


--
-- Name: stake_pool FK_stake_pool_last_retirement_id; Type: FK CONSTRAINT; Schema: public; Owner: postgres
--

ALTER TABLE ONLY public.stake_pool
    ADD CONSTRAINT "FK_stake_pool_last_retirement_id" FOREIGN KEY (last_retirement_id) REFERENCES public.pool_retirement(id) ON DELETE SET NULL;


--
-- PostgreSQL database dump complete
--

