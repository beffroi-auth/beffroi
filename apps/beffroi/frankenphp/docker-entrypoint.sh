#!/bin/sh
set -e

if [ "$1" = 'frankenphp' ] || [ "$1" = 'php' ] || [ "$1" = 'bin/console' ]; then
	if [ "$1" = 'frankenphp' ]; then
		docker-request-bounds
	fi

	# Install the project the first time PHP is started
	# After the installation, the following block can be deleted
	if [ ! -f composer.json ]; then
		echo "composer.json not found, this image expects the application in /app" >&2
		exit 1
	fi

	if [ "$APP_ENV" != 'prod' ] && [ ! -d vendor ]; then
		composer install --prefer-dist --no-progress --no-interaction
	fi

	if grep -q ^DATABASE_URL= .env 2>/dev/null; then
		echo "Waiting for database to be ready..."
		ATTEMPTS_LEFT_TO_REACH_DATABASE=60
		until [ $ATTEMPTS_LEFT_TO_REACH_DATABASE -eq 0 ] || DATABASE_ERROR=$(php bin/console dbal:run-sql -q "SELECT 1" 2>&1); do
			if [ $? -eq 255 ]; then
				# If the Doctrine command exits with 255, an unrecoverable error occurred
				ATTEMPTS_LEFT_TO_REACH_DATABASE=0
				break
			fi
			sleep 1
			ATTEMPTS_LEFT_TO_REACH_DATABASE=$((ATTEMPTS_LEFT_TO_REACH_DATABASE - 1))
			echo "Still waiting for database to be ready... Or maybe the database is not reachable. $ATTEMPTS_LEFT_TO_REACH_DATABASE attempts left."
		done

		if [ $ATTEMPTS_LEFT_TO_REACH_DATABASE -eq 0 ]; then
			echo "The database is not up or not reachable:"
			echo "$DATABASE_ERROR"
			exit 1
		else
			echo "The database is now ready and reachable"
		fi

		# The migrations of the bundle (beffroi_* tables) come with its migrations path, not from ./migrations.
		# The HTTP server migrates, then writes the row of the tenant its environment describes; a worker
		# (compose.yaml) starts once it is healthy and finds both. BEFFROI_MIGRATIONS_DATABASE_URL names the role
		# that owns the tables: it plays the migrations, and grants the role of DATABASE_URL when it is another.
		if [ "$1" = 'frankenphp' ]; then
			MIGRATIONS_DATABASE_URL="${BEFFROI_MIGRATIONS_DATABASE_URL:-$DATABASE_URL}"
			DATABASE_URL="$MIGRATIONS_DATABASE_URL" php bin/console doctrine:migrations:migrate --no-interaction --all-or-nothing
			RUNTIME_ROLE=$(php -r 'echo rawurldecode((string) parse_url((string) getenv("DATABASE_URL"), PHP_URL_USER));')
			OWNER_ROLE=$(MIGRATIONS_DATABASE_URL="$MIGRATIONS_DATABASE_URL" php -r 'echo rawurldecode((string) parse_url((string) getenv("MIGRATIONS_DATABASE_URL"), PHP_URL_USER));')
			if [ -n "$RUNTIME_ROLE" ] && [ "$RUNTIME_ROLE" != "$OWNER_ROLE" ]; then
				DATABASE_URL="$MIGRATIONS_DATABASE_URL" php bin/console beffroi:database:grant "$RUNTIME_ROLE" --no-interaction
			fi
			php bin/console beffroi:tenant:synchronize --no-interaction
		fi
	fi

	if [ "$APP_ENV" != 'prod' ] && [ "$1" = 'frankenphp' ]; then
		# The stylesheet of the pages: the DaisyUI plugin from the import map, then the Tailwind build
		# (the binary is downloaded into var/tailwind the first time). The production image builds at image time.
		php bin/console importmap:install --no-interaction
		php bin/console tailwind:build --no-interaction
	fi

	setfacl -R -m u:www-data:rwX -m u:"$(whoami)":rwX var 2>/dev/null || true
	setfacl -dR -m u:www-data:rwX -m u:"$(whoami)":rwX var 2>/dev/null || true

	echo "PHP app ready!"
fi

exec docker-php-entrypoint "$@"
