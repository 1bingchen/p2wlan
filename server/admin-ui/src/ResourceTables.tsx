import { useMemo } from 'react'
import { type ColumnDef } from '@tanstack/react-table'
import { Link, useLocation } from 'react-router-dom'
import { tr } from './i18n'
import { connectionLink, relationshipLink, resourceOriginState } from './pageState'
import { CopyValue } from './CopyValue'
import { DataTable, Status, natLabel, formatAgo } from './ResourceUI'
import type { AdminDevice, AdminNetwork, AdminRoom } from './types'

export function DeviceTable({ devices, accountId }: { devices: AdminDevice[]; accountId?: string }) {
  const location = useLocation()
  const columns = useMemo<ColumnDef<AdminDevice, unknown>[]>(() => [
    { id: 'device', header: '设备', cell: ({ row }) => <div className="primary-secondary"><Link state={resourceOriginState(location)} to={connectionLink({ deviceId: row.original.id, accountId })}>{row.original.device_name}</Link><span>{row.original.platform} · {row.original.app_version || tr('未知版本')}</span><TechnicalInfo key={row.original.id} id={row.original.id} name={row.original.device_name} label="设备 ID" copyLabel="复制设备 ID" facts={[{ label: 'NAT', value: natLabel(row.original.nat_type) }, { label: 'Relay RTT', value: row.original.relay_rtt_ms === undefined ? '—' : `${row.original.relay_rtt_ms} ms` }]} /></div> },
    { id: 'status', header: '状态', cell: ({ row }) => <Status online={row.original.online} /> },
    { id: 'owner', header: '账号', cell: ({ row }) => row.original.owner_id ? <Link state={resourceOriginState(location)} to={`/accounts/${encodeURIComponent(row.original.owner_id)}`}>{row.original.username}</Link> : row.original.username },
    { id: 'network_name', header: '网络', cell: ({ row }) => <Link state={resourceOriginState(location)} to={relationshipLink(row.original.network_id, row.original.network_id === 'default' ? row.original.owner_id : accountId)}>{row.original.network_name}</Link> },
    { id: 'ip', header: 'Virtual IP', cell: ({ row }) => <span className="resource-primary-value"><code>{row.original.virtual_ip}</code><CopyValue compact value={row.original.virtual_ip} label="复制虚拟 IP" /></span> },
    { id: 'last', header: '最后活动', cell: ({ row }) => formatAgo(row.original.last_seen) },
  ], [accountId, location])
  return <DataTable<AdminDevice> columns={columns} data={devices} empty={tr("没有符合条件的设备")} />
}

export function NetworkTable({ networks, accountId }: { networks: AdminNetwork[]; accountId?: string }) {
  const location = useLocation()
  const columns = useMemo<ColumnDef<AdminNetwork, unknown>[]>(() => [
    { id: 'name', header: '网络', cell: ({ row }) => <div className="primary-secondary"><Link state={resourceOriginState(location)} to={relationshipLink(row.original.id, accountId)}>{row.original.name}</Link><TechnicalInfo key={row.original.id} id={row.original.id} name={row.original.name} label="网络 ID" copyLabel="复制网络 ID" /></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { id: 'owner', header: '所有者', cell: ({ row }) => row.original.owner_id ? <Link state={resourceOriginState(location)} to={`/accounts/${encodeURIComponent(row.original.owner_id)}`}>{row.original.owner_username}</Link> : row.original.owner_username },
    { accessorKey: 'member_count', header: 'Members' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} ${tr('在线')}` },
    { id: 'type', header: '类型', cell: ({ row }) => <span className={`badge ${row.original.is_room ? 'purple' : ''}`}>{tr(row.original.is_room ? '房间网络' : '普通网络')}</span> },
    { id: 'connections', header: '连接', cell: ({ row }) => <Link state={resourceOriginState(location)} className="text-link" to={connectionLink({ networkId: row.original.id, accountId })}>{tr('查看连接')}</Link> },
  ], [accountId, location])
  return <DataTable<AdminNetwork> columns={columns} data={networks} empty={tr("暂无网络")} />
}

export function RoomTable({ rooms, accountId }: { rooms: AdminRoom[]; accountId?: string }) {
  const location = useLocation()
  const columns = useMemo<ColumnDef<AdminRoom, unknown>[]>(() => [
    { id: 'name', header: '房间', cell: ({ row }) => <div className="primary-secondary"><Link state={resourceOriginState(location)} to={relationshipLink(row.original.id, accountId)}>{row.original.name}</Link><div className="resource-primary-value"><code>#{row.original.code}</code><CopyValue compact value={row.original.code} label="复制房间码" /></div><TechnicalInfo key={row.original.id} id={row.original.id} name={row.original.name} label="房间 ID" copyLabel="复制房间 ID" /></div> },
    { id: 'cidr', header: 'CIDR', cell: ({ row }) => <span className="mono">{row.original.cidr}</span> },
    { id: 'owner', header: '所有者', cell: ({ row }) => row.original.owner_id ? <Link state={resourceOriginState(location)} to={`/accounts/${encodeURIComponent(row.original.owner_id)}`}>{row.original.owner_username}</Link> : row.original.owner_username },
    { accessorKey: 'member_count', header: 'Members' },
    { id: 'devices', header: '设备', cell: ({ row }) => `${row.original.online_devices}/${row.original.device_count} ${tr('在线')}` },
    { id: 'join', header: '加入', cell: ({ row }) => <span className={`badge ${row.original.join_locked ? 'warning' : 'success'}`}>{tr(row.original.join_locked ? '已锁定' : '可加入')}</span> },
    { id: 'connections', header: '连接', cell: ({ row }) => <Link state={resourceOriginState(location)} className="text-link" to={connectionLink({ networkId: row.original.id, accountId })}>{tr('查看连接')}</Link> },
  ], [accountId, location])
  return <DataTable<AdminRoom> columns={columns} data={rooms} empty={tr("暂无房间")} />
}

function TechnicalInfo({ id, name, label, copyLabel, facts = [] }: { id: string; name: string; label: string; copyLabel: string; facts?: { label: string; value: string }[] }) {
  return <details className="resource-technical-info">
    <summary aria-label={`${tr('技术信息')}: ${name}`}>{tr('技术信息')}</summary>
    <dl><div><dt>{tr(label)}</dt><dd><code>{id}</code><CopyValue compact value={id} label={copyLabel} /></dd></div>
      {facts.map((fact) => <div key={fact.label}><dt>{tr(fact.label)}</dt><dd>{fact.value}</dd></div>)}
    </dl>
  </details>
}
