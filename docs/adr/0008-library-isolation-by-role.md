# Each Service gets the minimal storage access its Roles need

The goal is to limit what a fully compromised Service can destroy: a Media Server must not be able to write to any Library, and an Organizer must not be able to change any Library but its own. Access is scoped by what each Service mounts. Each Library is its own folder under the Host's media root, and a Service holding several Roles gets the union of what those Roles need, and nothing more:

- **Music Videos**: Fuzzbin is its Requester, Downloader and Organizer, and mounts it read-write. It mounts no other Library.
- **Other Videos** and **TV**: filled by hand, with no Organizer. No Service writes to them.
- **ErsatzTV** is a Media Server and mounts the Libraries it presents read-only.
- **Dispatcharr** gets no Library access; its DVR is unused.

Media bind mounts never create their source (`create_host_path: false`): a missing folder fails the Deploy, instead of Docker creating an empty folder that a Media Server would present as an emptied Library.

## Considered Options

- **One media mount for every Service**: rejected; it gives every Service write access to every Library.
