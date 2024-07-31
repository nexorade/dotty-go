FROM golang:1.22-alpine as build

WORKDIR /app

COPY . .

RUN go mod download

RUN go build -o /dotty-go .

FROM scratch

COPY --from=build /dotty-go /dotty-go

VOLUME [ "/repository_storage" ]

EXPOSE 8080

CMD [ "/dotty-go" ]