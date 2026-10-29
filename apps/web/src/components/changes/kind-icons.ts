import type { ChangeKind } from '@exdomainvault/shared';
import {
  Boxes,
  DoorOpen,
  FileLock2,
  Globe,
  Landmark,
  Network,
  Package,
  Server,
  type LucideIcon,
} from 'lucide-react';

/** One icon per change kind (the kind's name is always given in text too). */
export const KIND_ICONS: Record<ChangeKind, LucideIcon> = {
  dns: Network,
  ip: Server,
  tls: FileLock2,
  http: Globe,
  port: DoorOpen,
  software: Package,
  registration: Landmark,
  asset: Boxes,
};
