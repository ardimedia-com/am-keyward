// Makes the top-level-statement entry point visible to WebApplicationFactory<Program> in the tests, which boot
// the reference shell for real (a startup that throws — e.g. a minimal-API parameter binding error — must fail a
// test, not a deployment).
public partial class Program;
