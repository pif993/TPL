(() => {
	class DashboardRouteControl {
		constructor(fetcher) {
			this.fetcher = fetcher;
			this.map = {
				health: '/monitoring/health',
				security: '/security/status',
				users: '/users',
				audit: '/audit/logs',
				modules: '/modules/state',
				ai: '/ai/log-analysis',
				templates: '/template/list',
				lang: '/engine/lang/strings',
				router: '/router/status'
			};
			this.usingFallback = true;
		}

		async init() {
			try {
				const data = await this.fetcher('/api/r/map');
				const shorthandRoutes = data?.shorthand_routes || {};
				const fromApi = {};

				Object.keys(shorthandRoutes).forEach((key) => {
					fromApi[key] = shorthandRoutes[key]?.full_path;
				});

				if (Object.keys(fromApi).length > 0) {
					this.map = fromApi;
					this.usingFallback = false;
				}
			} catch (_) {
				this.usingFallback = true;
			}
			return this;
		}

		getPath(alias) {
			return this.map[alias] || null;
		}

		async call(alias, options = {}) {
			const path = this.getPath(alias);
			if (!path) throw new Error(`Unknown route alias: ${alias}`);

			const query = options.query || null;
			const queryString = query ? `?${new URLSearchParams(query).toString()}` : '';

			return this.fetcher(`/api${path}${queryString}`, options.fetchOptions || {});
		}

		async routerStatus() {
			return this.fetcher('/api/router/status');
		}

		aliases() {
			return Object.keys(this.map);
		}
	}

	window.DashboardRouteControl = DashboardRouteControl;
})();
