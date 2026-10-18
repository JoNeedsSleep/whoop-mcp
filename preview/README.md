# Sample viewer

Static, fictional WHOOP data for the local preview. The page deliberately uses
plain HTML and CSS with no JavaScript, external assets, account connection or
data fetching. It is not a production health-data endpoint.

The isolated preview server serves this page at `/` and `/preview/dataset.html`;
`Settings` opens the existing synthetic dashboard. Keep the preview loopback-only,
without host mounts, credentials or outbound access, as described in
`SECURITY_REVIEW.md`. These files are not part of the production web build.
