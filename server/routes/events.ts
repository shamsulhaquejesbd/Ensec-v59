import type express from 'express';
import { resolveRequestUser } from '../auth/authService.ts';

export interface ErpRealtimeEventPayload {
  table: string;
  eventType: 'INSERT' | 'UPDATE' | 'DELETE';
  newRow?: Record<string, any> | null;
  oldRow?: Record<string, any> | null;
  timestamp: string;
}

interface SseClient {
  id: string;
  userId: string;
  res: express.Response;
}

const activeSseClients = new Map<string, SseClient>();

function sanitizeRealtimeRow(table: string, row: any): Record<string, any> | null {
  if (!row || typeof row !== 'object') return null;
  if (table === 'users') {
    const { password: _p, password_hash: _ph, ...rest } = row;
    return rest;
  }
  return row;
}

export function emitErpTableEvent(event: Omit<ErpRealtimeEventPayload, 'timestamp'>) {
  if (activeSseClients.size === 0) return;

  const payload: ErpRealtimeEventPayload = {
    table: event.table,
    eventType: event.eventType,
    newRow: sanitizeRealtimeRow(event.table, event.newRow),
    oldRow: sanitizeRealtimeRow(event.table, event.oldRow),
    timestamp: new Date().toISOString(),
  };

  const frame = `event: db-change\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const [clientId, client] of activeSseClients.entries()) {
    try {
      client.res.write(frame);
    } catch {
      activeSseClients.delete(clientId);
    }
  }
}

export function registerEventsRoutes(app: express.Application) {
  app.get('/api/erp/events', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        ok: false,
        code: 'EVENTS_UNAUTHORIZED',
        error: 'Authentication required to subscribe to real-time ERP updates.',
      });
    }

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof (res as any).flushHeaders === 'function') {
      (res as any).flushHeaders();
    }

    const clientId = `sse-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    activeSseClients.set(clientId, {
      id: clientId,
      userId: caller.id,
      res,
    });

    res.write(
      `event: connected\ndata: ${JSON.stringify({
        ok: true,
        clientId,
        timestamp: new Date().toISOString(),
      })}\n\n`
    );

    const heartbeat = setInterval(() => {
      try {
        res.write(`event: ping\ndata: ${JSON.stringify({ ts: Date.now() })}\n\n`);
      } catch {
        clearInterval(heartbeat);
        activeSseClients.delete(clientId);
      }
    }, 25000);

    req.on('close', () => {
      clearInterval(heartbeat);
      activeSseClients.delete(clientId);
    });
  });
}
