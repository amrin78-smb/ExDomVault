// Types for the npm `punycode` package's ES module build, imported by explicit path.
declare module 'punycode/punycode.es6.js' {
  const punycode: {
    toUnicode(input: string): string;
    toASCII(input: string): string;
  };
  export default punycode;
}
