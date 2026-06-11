// Ambient declaration for cytoscape-cola, which ships no types and has no
// @types package. Covers only the surface this app uses.
declare module 'cytoscape-cola' {
  import type cytoscape from 'cytoscape'

  const cola: cytoscape.Ext
  export default cola
}

// Options accepted by cy.layout({ name: 'cola', ... }). Kept permissive on
// purpose so upstream option churn does not break the build.
interface ColaLayoutOptions extends Record<string, unknown> {
  name: 'cola'
  infinite?: boolean
  animate?: boolean
  fit?: boolean
  centerGraph?: boolean
  nodeSpacing?: number
  edgeLength?: number | ((edge: import('cytoscape').EdgeSingular) => number)
  avoidOverlap?: boolean
  ungrabifyWhileSimulating?: boolean
  randomize?: boolean
}
