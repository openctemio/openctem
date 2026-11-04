### Changed: web image size budget 330 MB

- The image guard's budget for `openctem-web` is 330 MB (was 300 MB). v0.19.0's web image is 302 MB, mostly the open-source notices data, so Docker Publish refused it and skipped signing every image.
