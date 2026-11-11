// Output pane — the fixed primary surface. xterm + toolbar land in Task 4; this
// is the container placeholder.
export function OutputPane() {
  return (
    <div className="output" data-testid="output-pane">
      <div className="otool"><span className="ttl">Output</span></div>
      <div className="obody" />
    </div>
  );
}
