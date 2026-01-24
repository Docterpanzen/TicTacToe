import { environment } from '../../environments/environment';

const normalizeBase = (value: string): string => value.replace(/\/$/, '');

const apiBaseUrl = normalizeBase(environment.apiBaseUrl || '');

export const buildApiUrl = (path: string): string => `${apiBaseUrl}${path}`;

export const resolveWsBaseUrl = (): string => {
  if (environment.wsBaseUrl) {
    return normalizeBase(environment.wsBaseUrl);
  }

  const protocol = location.protocol === 'https:' ? 'wss' : 'ws';
  return `${protocol}://${location.host}`;
};
