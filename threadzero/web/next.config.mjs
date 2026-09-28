/** Static export: `npm run build` produces web/out which the Python server (`threadzero serve`) hosts. */
const nextConfig = {
  output: 'export',
  trailingSlash: true,
  reactStrictMode: true,
  images: { unoptimized: true },
  transpilePackages: ['three'],
};
export default nextConfig;
