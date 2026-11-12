import { useState } from 'react';
import { ValueNode, isBranch, leafText, preview } from '../../repl/valueTree';
import { addrMenu, openAddressMenu } from '../../addressMenu';
import { Icon } from '../Icon';

// A value as an expandable tree: containers open and close, and a pointer is
// an address with the address menu (click or right-click).
export function ValueTree({ node, name, open = false }: { node: ValueNode; name?: string; open?: boolean }) {
  const [expanded, setExpanded] = useState(open);
  const key = name !== undefined ? <span className="vk">{name}: </span> : null;

  if (!isBranch(node)) {
    return (
      <div className="vrow" data-testid="value-leaf">
        <span className="vpad" />
        {key}
        {node.t === 'ptr'
          ? (
            <button
              className="vv ptr"
              data-testid="value-pointer"
              title="Address: click for the address menu"
              {...addrMenu(node.v)}
              onClick={(e) => { const r = e.currentTarget.getBoundingClientRect(); openAddressMenu(node.v, r.left, r.bottom + 2); }}
            >
              {node.v}
            </button>
          )
          : <span className={'vv ' + node.t}>{leafText(node)}</span>}
      </div>
    );
  }

  const empty = node.kids.length === 0 && node.more === 0;
  return (
    <div className="vnode" data-testid="value-node">
      <button className="vrow vhead" aria-expanded={expanded} disabled={empty} onClick={() => setExpanded(!expanded)}>
        <span className={'vpad chev' + (expanded ? ' open' : '')}>{!empty && <Icon name="chevron" size={10} />}</span>
        {key}
        <span className="vsum">{expanded ? (node.t === 'arr' ? `Array(${node.n})` : node.label) : preview(node)}</span>
      </button>
      {expanded && (
        <div className="vkids">
          {node.kids.map((kid, i) => <ValueTree key={kid.k + ':' + i} node={kid.v} name={kid.k} />)}
          {node.more > 0 && <div className="vrow vmore"><span className="vpad" />… {node.more.toLocaleString()} more not shown</div>}
        </div>
      )}
    </div>
  );
}
