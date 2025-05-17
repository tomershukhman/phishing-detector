declare module "*.json" {
  const value: any;
  export default value;
}

declare module "*.css" {
  const content: Record<string, string>;
  export default content;
}

declare module "*.css" {
  const css: string;
  export default css;
}
