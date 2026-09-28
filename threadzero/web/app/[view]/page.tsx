import ViewHost from '@/components/shell/ViewHost';
import { VIEW_IDS } from '@/views/ids';

export const dynamicParams = false;
export function generateStaticParams() { return VIEW_IDS.map((view) => ({ view })); }
export default function Page({ params }: { params: { view: string } }) { return <ViewHost view={params.view} />; }
