CREATE TABLE public.role_table
(
    id bigint NOT NULL,
    label character varying(255) COLLATE pg_catalog."default",
    value character varying(255) COLLATE pg_catalog."default",
    CONSTRAINT role_table_pkey PRIMARY KEY (id)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.role_table
    OWNER to postgres;