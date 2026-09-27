default: build

.include "env.mk"

PUBKEY=/t/rum/public.pem

build:
	@ rm -f mås
	@ go fmt
	GOARCH=amd64 GOOS=${goos} \
		go build \
		-ldflags '-s' \
		-o mås

#	./mås -secretkey abcdef -role admin -role test
#	./mås -test -pubkeyfile ${PUBKEY} -role admin -role test

develop-jwt:
	@ rm -f mås
	@ go run mås.go -role ${ROLE} -dir ${DIR} -pubkeyfile ${PUBKEY}

develop-bauth:
	@ rm -f mås
	@ go run mås.go -bauth -user ${USER} -password ${PASSWD} -dir ${DIR}
