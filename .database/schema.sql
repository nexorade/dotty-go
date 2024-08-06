-- Create "app_user" table
CREATE TABLE app_user (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    photo_url VARCHAR(255) NOT NULL DEFAULT 'https://robohash.org/71d2d83d09151874f9bdfecc0da05d6a?set=set4&bgset=&size=400x400',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL
);

-- Create "refresh_token" table
CREATE TABLE refresh_token (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    token VARCHAR(255) NOT NULL,
    client_ip VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
);


-- Create "preferences" table
CREATE TABLE preferences (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    dark_mode BOOLEAN NOT NULL DEFAULT TRUE,
    codespace_theme VARCHAR(255) NOT NULL DEFAULT 'dracula',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE
);

-- Create "path" table
CREATE TABLE dotsource_path (
    id SERIAL PRIMARY KEY,
    base_path VARCHAR(255) NOT NULL DEFAULT '/repository_storage',
    relative_path VARCHAR(255) DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL
);


-- Create "dotsource" table
CREATE TABLE dotsource (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    dotsource_path_id INTEGER NOT NULL,
    name VARCHAR(255) NOT NULL,
    private BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMPTZ DEFAULT NULL,
    FOREIGN KEY (user_id) REFERENCES app_user(id) ON DELETE CASCADE,
    FOREIGN KEY (dotsource_path_id) REFERENCES dotsource_path(id) ON DELETE CASCADE
);
