# The image goreleaser publishes: the release's binary on a distroless base.
FROM gcr.io/distroless/static-debian12:nonroot
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/novaro /usr/local/bin/novaro
ENTRYPOINT ["/usr/local/bin/novaro"]
