import React, { useRef, useEffect } from 'react';
import { Search, X, Filter } from 'lucide-react';

interface SearchBarProps {
  searchQuery: string;
  onSearchChange: (query: string) => void;
  activeCategory: string;
  onCategoryChange: (category: string) => void;
  categories: { id: string; label: string; count?: number }[];
}

export const SearchBar: React.FC<SearchBarProps> = ({
  searchQuery,
  onSearchChange,
  activeCategory,
  onCategoryChange,
  categories,
}) => {
  const inputRef = useRef<HTMLInputElement>(null);

  // Global ⌘K shortcut to focus search
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        inputRef.current?.focus();
        inputRef.current?.select();
      }
      if (e.key === 'Escape' && document.activeElement === inputRef.current) {
        if (searchQuery) {
          onSearchChange('');
        } else {
          inputRef.current?.blur();
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [searchQuery, onSearchChange]);

  return (
    <div className="space-y-2 select-none">
      {/* Search Input Box */}
      <div className="relative flex items-center">
        <div className="absolute left-3 flex items-center pointer-events-none text-gray-400">
          <Search className="w-3.5 h-3.5" />
        </div>
        <input
          ref={inputRef}
          type="text"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder="Filter secrets by name or prefix... (⌘K)"
          className="w-full pl-9 pr-16 py-2 bg-inset text-gray-200 placeholder-gray-400 text-xs font-mono rounded border border-subpixel focus:border-radar-core focus:ring-1 focus:ring-radar-core/40 focus:outline-none transition-all shadow-subtle-inset"
        />

        {/* Action icons / shortcut hint */}
        <div className="absolute right-2.5 flex items-center gap-1.5">
          {searchQuery ? (
            <button
              onClick={() => onSearchChange('')}
              className="p-1 text-gray-400 hover:text-gray-200 rounded hover:bg-surface transition-colors cursor-pointer"
              title="Clear search (Esc)"
            >
              <X className="w-3 h-3" />
            </button>
          ) : (
            <kbd className="hidden sm:inline-flex items-center px-1.5 py-0.5 text-[10px] font-mono text-gray-400 bg-surface rounded border border-subpixel">
              ⌘K
            </kbd>
          )}
        </div>
      </div>

      {/* Filter Category Badges */}
      <div className="flex items-center gap-1.5 overflow-x-auto pb-1 text-[11px] font-mono no-scrollbar">
        <span className="text-gray-400 text-[10px] uppercase font-bold flex items-center gap-1 pl-0.5 pr-1">
          <Filter className="w-3 h-3 text-radar-core" />
          TAG:
        </span>
        {categories.map((cat) => {
          const isActive = activeCategory === cat.id;
          return (
            <button
              key={cat.id}
              onClick={() => onCategoryChange(cat.id)}
              className={`px-2 py-0.5 rounded transition-all whitespace-nowrap cursor-pointer border ${
                isActive
                  ? 'bg-radar-dim text-radar-glow border-radar-border font-semibold shadow-radar-glow-sm'
                  : 'bg-inset text-gray-400 hover:text-gray-200 border-subpixel hover:bg-elevated'
              }`}
            >
              {cat.label}
              {cat.count !== undefined && (
                <span className="ml-1 opacity-70">({cat.count})</span>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
};
