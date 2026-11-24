FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /server .

FROM gcr.io/distroless/static
COPY --from=build /server /server
EXPOSE 8080
CMD ["/server"]
