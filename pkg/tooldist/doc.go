// Package tooldist validates and unpacks tool distribution packages (ZIP)
// uploaded by an administrator.
//
// A package is untrusted input that will eventually be built into a container,
// so validation is deliberately strict and happens before anything is written
// to disk:
//
//   - the ZIP must be readable and within the compressed size cap;
//   - every entry path must be a clean relative forward-slash path (no absolute
//     paths, no drive letters, no ".." segments) so extraction can never escape
//     the target directory (zip-slip);
//   - the expanded size and entry count are bounded (zip-bomb defence);
//   - manifest.json and Dockerfile must exist at the package root;
//   - manifest identity fields must be well-formed.
//
// Nothing in this package executes code or contacts the network.
package tooldist
