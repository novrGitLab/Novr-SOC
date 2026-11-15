import { redirect } from 'next/navigation';

// The V2 web app has no public landing page (the marketing site is a separate project, D-22).
export default function Root() {
    redirect('/app');
}
