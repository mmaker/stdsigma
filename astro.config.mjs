// @ts-check
import { defineConfig } from 'astro/config';
import tailwindcss from "@tailwindcss/vite";
import mdx from '@astrojs/mdx';
import rehypeKatex from 'rehype-katex';
import remarkMath from 'remark-math';


export default defineConfig({
  site: "https://sigma.zkproof.org",
  vite: {
      plugins: [tailwindcss()],
  },
  integrations: [mdx()],
  markdown: {
    rehypePlugins: [rehypeKatex],
    remarkPlugins: [remarkMath]
  },
});