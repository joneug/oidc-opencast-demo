OPENCAST_VERSION=9.3

.PHONY: build
build:
	if [ ! -d "opencast/" ]; then \
		git clone https://github.com/opencast/opencast.git; \
	fi
	cd opencast/ && git checkout -f '${OPENCAST_VERSION}' \
	             && git apply ../patches/00-pom.patch \
	             && git apply ../patches/01-karaf-features.patch \
				 && cp -r ../security-jwt modules/ \
	             && mvn clean install -Pdev -DskipTests -DskipJasmineTests=true

.PHONY: start
start:
	cd opencast/docs/scripts/devel-dependency-containers && docker-compose up -d
	docker-compose up -d
	sleep 30s
	rm -r opencast/build/opencast-dist-develop-*/data/*
	cp assets/mh_default_org.xml opencast/build/opencast-dist-develop-*/etc/security
	cd opencast/build/opencast-dist-develop-* && ./bin/start-opencast

.PHONY: stop
stop:
	cd opencast/docs/scripts/devel-dependency-containers && docker-compose rm -s -f
	docker-compose rm -s -f

.PHONY: clean
clean:
	rm -rf opencast
	rm -rf build
