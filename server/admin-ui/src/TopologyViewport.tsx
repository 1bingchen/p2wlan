import { useEffect } from 'react'
import { getNodesBounds, getViewportForBounds, type Node, useReactFlow, useStore } from '@xyflow/react'

interface TopologyViewportProps {
  nodes: Node[]
  fullscreen: boolean
  padding?: number
  maxZoom?: number
  focusNodeIds?: string[]
  focusKey?: string
}

/** Fit structural changes without resetting a user's view on telemetry updates. */
export function TopologyViewport({ nodes, fullscreen, padding = 0.12, maxZoom = 1.12, focusNodeIds = [], focusKey = '' }: TopologyViewportProps) {
  const { setViewport, viewportInitialized } = useReactFlow()
  const width = useStore((state) => state.width)
  const height = useStore((state) => state.height)
  const focused = nodes.filter((node) => focusNodeIds.includes(node.id))
  const bounds = getNodesBounds(focused.length ? focused : nodes)
  const nodeIds = nodes.map((node) => node.id).sort().join('\n')

  useEffect(() => {
    if (!viewportInitialized || !nodeIds || width <= 0 || height <= 0) return
    const frame = window.requestAnimationFrame(() => {
      void setViewport(getViewportForBounds(bounds, width, height, 0.08, maxZoom, padding))
    })
    return () => window.cancelAnimationFrame(frame)
    // All node dimensions are declared by the graph builders. Waiting for React
    // Flow's measured-node state can deadlock a read-only, controlled graph.
    // Telemetry-only node replacements deliberately do not reset the viewport.
  }, [viewportInitialized, nodeIds, focusKey, bounds.x, bounds.y, bounds.width, bounds.height, width, height, fullscreen, maxZoom, padding, setViewport])

  return null
}
