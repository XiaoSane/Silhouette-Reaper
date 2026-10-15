export async function register() {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { ForensicRepository } = await import('@/lib/db/database');
    try {
      ForensicRepository.cleanExpiredInvestigationsAndReports();
    } catch (e) {
      console.error('[Purge Daemon Startup Error]:', e);
    }

    // Schedule retention purge check every 10 minutes
    setInterval(() => {
      try {
        ForensicRepository.cleanExpiredInvestigationsAndReports();
      } catch (err) {
        console.error('[Purge Daemon Periodic Error]:', err);
      }
    }, 10 * 60 * 1000);
  }
}
