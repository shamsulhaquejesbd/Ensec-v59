import type express from 'express';
import { hasPageAction } from '../../src/types/pagePermissions.ts';
import {
  sanitizeProductionOrderForUser,
} from '../../src/lib/manufacturingPermissions.ts';
import {
  resolveOvertimePermissions,
  sanitizeOvertimeRecordForUser,
} from '../../src/lib/overtimePermissions.ts';
import {
  getServerSupabase,
  sanitizeDatabaseError,
} from '../db/index.ts';
import {
  hashPassword,
  indexUserInAuthCache,
  isBcryptHash,
  mapSupabaseUserRowSafe,
  resolveRequestUser,
  sanitizeUserForClient,
  type AuthenticatedErpUser,
} from '../auth/authService.ts';
import { emitErpTableEvent } from './events.ts';

type OperationType = 'select' | 'insert' | 'upsert' | 'update' | 'delete';

interface PageActionRule {
  pageId: string;
  actions: string[];
}

interface TableRbacRule {
  read: PageActionRule[];
  create: PageActionRule[];
  edit: PageActionRule[];
  delete: PageActionRule[];
}

const FINANCE_READ_RULES: PageActionRule[] = [
  { pageId: 'finance-cashbook', actions: ['view'] },
  { pageId: 'finance-accounting-dashboard', actions: ['view'] },
  { pageId: 'finance-coa', actions: ['view'] },
  { pageId: 'finance-opening-balances', actions: ['view'] },
  { pageId: 'finance-journal-vouchers', actions: ['view'] },
  { pageId: 'finance-general-ledger', actions: ['view'] },
  { pageId: 'finance-receivables', actions: ['view'] },
  { pageId: 'finance-payables', actions: ['view'] },
  { pageId: 'finance-trial-balance', actions: ['view'] },
  { pageId: 'finance-balance-sheet', actions: ['view'] },
  { pageId: 'finance-profit-loss', actions: ['view'] },
  { pageId: 'finance-cash-flow', actions: ['view'] },
  { pageId: 'finance-fiscal-years', actions: ['view'] },
  { pageId: 'dashboard', actions: ['view_revenue'] },
];

const FINANCE_WRITE_RULES: PageActionRule[] = [
  {
    pageId: 'finance-cashbook',
    actions: ['create_voucher', 'edit_voucher', 'approve_voucher', 'post_voucher', 'reverse_voucher', 'reconcile'],
  },
  { pageId: 'finance-coa', actions: ['create', 'edit'] },
  { pageId: 'finance-opening-balances', actions: ['create'] },
  { pageId: 'finance-journal-vouchers', actions: ['create', 'edit', 'approve', 'post', 'reverse'] },
  { pageId: 'finance-receivables', actions: ['collect'] },
  { pageId: 'finance-payables', actions: ['pay'] },
  { pageId: 'finance-fiscal-years', actions: ['create', 'lock_period', 'close_year'] },
];

const INSTALLMENT_READ_RULES: PageActionRule[] = [
  { pageId: 'installment', actions: ['view'] },
  { pageId: 'installment-dashboard', actions: ['view'] },
  { pageId: 'installment-agreements', actions: ['view'] },
  { pageId: 'installment-schedule', actions: ['view'] },
  { pageId: 'installment-customers', actions: ['view'] },
  { pageId: 'installment-due', actions: ['view'] },
  { pageId: 'installment-overdue', actions: ['view'] },
  { pageId: 'installment-payment-collection', actions: ['view'] },
  { pageId: 'installment-payment-history', actions: ['view'] },
  { pageId: 'installment-early-settlement', actions: ['view'] },
  { pageId: 'collection', actions: ['view'] },
  { pageId: 'collection-assignments', actions: ['view'] },
  { pageId: 'collection-followups', actions: ['view'] },
  ...FINANCE_READ_RULES,
  { pageId: 'reports', actions: ['view'] },
  { pageId: 'dashboard', actions: ['view'] },
];

const INSTALLMENT_WRITE_RULES: PageActionRule[] = [
  { pageId: 'installment', actions: ['create', 'edit', 'approve', 'collect', 'delete'] },
  { pageId: 'installment-new-plan', actions: ['create'] },
  { pageId: 'installment-agreements', actions: ['create', 'edit', 'approve', 'delete'] },
  { pageId: 'installment-payment-collection', actions: ['collect', 'create'] },
  { pageId: 'installment-early-settlement', actions: ['create', 'approve'] },
  { pageId: 'collection', actions: ['collect', 'edit'] },
];

const OVERTIME_READ_RULES: PageActionRule[] = [
  { pageId: 'overtime-management', actions: ['view', 'view_requests', 'view_attendance', 'view_batch_allocation', 'view_payroll_sync', 'view_policies', 'view_reports'] },
  { pageId: 'overtime-requests', actions: ['view'] },
  { pageId: 'overtime-attendance', actions: ['view'] },
  { pageId: 'overtime-batch-allocation', actions: ['view'] },
  { pageId: 'overtime-payroll-sync', actions: ['view'] },
  { pageId: 'overtime-policies', actions: ['view'] },
  { pageId: 'overtime-reports', actions: ['view'] },
  { pageId: 'payroll', actions: ['view'] },
  { pageId: 'manufacturing-costing', actions: ['view'] },
];

export const TABLE_RBAC_CONFIG: Record<string, TableRbacRule> = {
  // A. Users & Permissions & Org Hierarchy
  users: {
    read: [{ pageId: 'users-permissions', actions: ['view'] }],
    create: [{ pageId: 'users-permissions', actions: ['create'] }],
    edit: [{ pageId: 'users-permissions', actions: ['edit', 'assign_permissions', 'reset_password'] }],
    delete: [{ pageId: 'users-permissions', actions: ['delete'] }],
  },
  org_hierarchy: {
    read: [
      { pageId: 'basic-data-org-hierarchy', actions: ['view'] },
      { pageId: 'basic-data-distributors', actions: ['view'] },
      { pageId: 'basic-data-customers', actions: ['view'] },
      { pageId: 'basic-data-field-force', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'customers-crm', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'field-tracker', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-org-hierarchy', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-org-hierarchy', actions: ['edit', 'create'] }],
    delete: [{ pageId: 'basic-data-org-hierarchy', actions: ['delete'] }],
  },

  // B. Master Data
  products: {
    read: [
      { pageId: 'basic-data-products', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'stock-cid-receive', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'warehouse', actions: ['view'] },
      { pageId: 'installment', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'crm-agreements', actions: ['view'] },
      { pageId: 'basic-data-offers', actions: ['view'] },
      { pageId: 'basic-data-pricing-matrix', actions: ['view'] },
      { pageId: 'warranty', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-products', actions: ['create'] }],
    edit: [
      { pageId: 'basic-data-products', actions: ['edit'] },
      { pageId: 'basic-data-pricing-matrix', actions: ['edit', 'create'] },
      { pageId: 'manufacturing', actions: ['update_bom'] },
    ],
    delete: [{ pageId: 'basic-data-products', actions: ['delete'] }],
  },
  product_categories: {
    read: [
      { pageId: 'basic-data-categories', actions: ['view'] },
      { pageId: 'basic-data-products', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-categories', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-categories', actions: ['edit'] }],
    delete: [{ pageId: 'basic-data-categories', actions: ['delete'] }],
  },
  product_brands: {
    read: [
      { pageId: 'basic-data-brands', actions: ['view'] },
      { pageId: 'basic-data-products', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-brands', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-brands', actions: ['edit'] }],
    delete: [{ pageId: 'basic-data-brands', actions: ['delete'] }],
  },
  raw_materials: {
    read: [
      { pageId: 'basic-data-raw-materials', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'raw-material-receive', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'procurement', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'basic-data-raw-materials', actions: ['create', 'import_excel'] },
      { pageId: 'raw-material-receive', actions: ['create'] },
    ],
    edit: [
      { pageId: 'basic-data-raw-materials', actions: ['edit', 'import_excel'] },
      { pageId: 'raw-material-receive', actions: ['create', 'edit', 'approve'] },
      { pageId: 'manufacturing', actions: ['issue_materials', 'edit_issued_stock'] },
    ],
    delete: [{ pageId: 'basic-data-raw-materials', actions: ['delete'] }],
  },
  raw_material_categories: {
    read: [
      { pageId: 'basic-data-raw-categories', actions: ['view'] },
      { pageId: 'basic-data-raw-materials', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'raw-material-receive', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'procurement', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-raw-categories', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-raw-categories', actions: ['edit'] }],
    delete: [{ pageId: 'basic-data-raw-categories', actions: ['delete'] }],
  },
  raw_material_classifications: {
    read: [
      { pageId: 'basic-data-raw-classifications', actions: ['view'] },
      { pageId: 'basic-data-raw-categories', actions: ['view'] },
      { pageId: 'basic-data-raw-materials', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'raw-material-receive', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-raw-classifications', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-raw-classifications', actions: ['edit'] }],
    delete: [{ pageId: 'basic-data-raw-classifications', actions: ['delete'] }],
  },
  warehouses: {
    read: [
      { pageId: 'basic-data-warehouses', actions: ['view'] },
      { pageId: 'warehouse', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'stock-transfer', actions: ['view'] },
      { pageId: 'stock-cid-receive', actions: ['view'] },
      { pageId: 'stock-adjustment', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'basic-data-warehouses', actions: ['create'] },
      { pageId: 'warehouse', actions: ['create'] },
    ],
    edit: [
      { pageId: 'basic-data-warehouses', actions: ['edit', 'status_toggle'] },
      { pageId: 'warehouse', actions: ['edit', 'audit'] },
      { pageId: 'stock-cid-receive', actions: ['create', 'approve'] },
      { pageId: 'stock-transfer', actions: ['approve', 'receive'] },
    ],
    delete: [{ pageId: 'basic-data-warehouses', actions: ['delete'] }],
  },
  customer_categories: {
    read: [
      { pageId: 'basic-data-pricing-matrix', actions: ['view'] },
      { pageId: 'basic-data-customers', actions: ['view'] },
      { pageId: 'customers-crm', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-pricing-matrix', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-pricing-matrix', actions: ['edit', 'approve'] }],
    delete: [{ pageId: 'basic-data-pricing-matrix', actions: ['delete'] }],
  },
  customers: {
    read: [
      { pageId: 'basic-data-customers', actions: ['view'] },
      { pageId: 'customers-crm', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'installment', actions: ['view'] },
      { pageId: 'collection', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'warranty', actions: ['view'] },
      { pageId: 'crm-agreements', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'basic-data-customers', actions: ['create'] },
      { pageId: 'customers-crm', actions: ['create'] },
      { pageId: 'mobile-field', actions: ['place_order'] },
    ],
    edit: [
      { pageId: 'basic-data-customers', actions: ['edit', 'set_credit'] },
      { pageId: 'customers-crm', actions: ['edit'] },
    ],
    delete: [
      { pageId: 'basic-data-customers', actions: ['delete'] },
      { pageId: 'customers-crm', actions: ['delete'] },
    ],
  },
  distributors: {
    read: [
      { pageId: 'basic-data-distributors', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'installment', actions: ['view'] },
      { pageId: 'collection', actions: ['view'] },
      { pageId: 'customers-crm', actions: ['view'] },
      { pageId: 'basic-data-org-hierarchy', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'finance-cashbook', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'basic-data-distributors', actions: ['create'] },
      { pageId: 'basic-data-org-hierarchy', actions: ['create'] },
    ],
    edit: [
      { pageId: 'basic-data-distributors', actions: ['edit', 'approve_credit'] },
      { pageId: 'basic-data-org-hierarchy', actions: ['edit'] },
    ],
    delete: [{ pageId: 'basic-data-distributors', actions: ['delete'] }],
  },
  departments: {
    read: [
      { pageId: 'basic-data-departments', actions: ['view'] },
      { pageId: 'basic-data-field-force', actions: ['view'] },
      { pageId: 'payroll', actions: ['view'] },
      { pageId: 'overtime-management', actions: ['view'] },
      { pageId: 'users-permissions', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-departments', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-departments', actions: ['edit'] }],
    delete: [{ pageId: 'basic-data-departments', actions: ['delete'] }],
  },
  banks: {
    read: [
      { pageId: 'basic-data-banks', actions: ['view'] },
      ...FINANCE_READ_RULES,
      { pageId: 'payment', actions: ['view'] },
    ],
    create: [
      { pageId: 'basic-data-banks', actions: ['create'] },
      { pageId: 'finance-cashbook', actions: ['reconcile'] },
    ],
    edit: [
      { pageId: 'basic-data-banks', actions: ['edit'] },
      { pageId: 'finance-cashbook', actions: ['reconcile'] },
    ],
    delete: [{ pageId: 'basic-data-banks', actions: ['delete'] }],
  },
  units_of_measurement: {
    read: [
      { pageId: 'basic-data-uom', actions: ['view'] },
      { pageId: 'basic-data-products', actions: ['view'] },
      { pageId: 'basic-data-raw-materials', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'procurement', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-uom', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-uom', actions: ['edit'] }],
    delete: [{ pageId: 'basic-data-uom', actions: ['delete'] }],
  },
  field_force_reps: {
    read: [
      { pageId: 'basic-data-field-force', actions: ['view'] },
      { pageId: 'field-tracker', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'payroll', actions: ['view'] },
      ...OVERTIME_READ_RULES,
      { pageId: 'tada', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'collection', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-field-force', actions: ['create'] }],
    edit: [
      { pageId: 'basic-data-field-force', actions: ['edit', 'assign_target'] },
      { pageId: 'payroll', actions: ['edit'] },
    ],
    delete: [{ pageId: 'basic-data-field-force', actions: ['delete'] }],
  },
  office_locations: {
    read: [
      { pageId: 'basic-data-warehouses', actions: ['view'] },
      { pageId: 'payroll', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      ...OVERTIME_READ_RULES,
      { pageId: 'field-tracker', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'basic-data-warehouses', actions: ['create'] },
      { pageId: 'payroll', actions: ['create', 'edit'] },
    ],
    edit: [
      { pageId: 'basic-data-warehouses', actions: ['edit'] },
      { pageId: 'payroll', actions: ['edit'] },
    ],
    delete: [
      { pageId: 'basic-data-warehouses', actions: ['delete'] },
      { pageId: 'payroll', actions: ['edit'] },
    ],
  },
  offers_promotions: {
    read: [
      { pageId: 'basic-data-offers', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'basic-data-offers', actions: ['create'] }],
    edit: [{ pageId: 'basic-data-offers', actions: ['edit', 'approve'] }],
    delete: [{ pageId: 'basic-data-offers', actions: ['delete'] }],
  },

  // C. Inventory & Supply Chain
  raw_material_receipts: {
    read: [
      { pageId: 'raw-material-receive', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'procurement', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      ...FINANCE_READ_RULES,
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'raw-material-receive', actions: ['create'] },
      { pageId: 'procurement', actions: ['create'] },
    ],
    edit: [
      { pageId: 'raw-material-receive', actions: ['edit', 'approve'] },
      { pageId: 'procurement', actions: ['edit', 'approve'] },
    ],
    delete: [
      { pageId: 'raw-material-receive', actions: ['delete'] },
      { pageId: 'procurement', actions: ['delete'] },
    ],
  },
  raw_material_receipt_items: {
    read: [
      { pageId: 'raw-material-receive', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'procurement', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
    ],
    create: [{ pageId: 'raw-material-receive', actions: ['create'] }],
    edit: [{ pageId: 'raw-material-receive', actions: ['edit', 'approve'] }],
    delete: [{ pageId: 'raw-material-receive', actions: ['delete'] }],
  },
  inventory_batches: {
    read: [
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'raw-material-receive', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'procurement', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'raw-material-receive', actions: ['create', 'approve'] },
      { pageId: 'manufacturing', actions: ['issue_materials'] },
    ],
    edit: [
      { pageId: 'raw-material-receive', actions: ['edit', 'approve'] },
      { pageId: 'manufacturing', actions: ['issue_materials', 'edit_issued_stock'] },
      { pageId: 'stock-adjustment', actions: ['create', 'approve'] },
    ],
    delete: [{ pageId: 'raw-material-receive', actions: ['delete'] }],
  },
  inventory_movements: {
    read: [
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'raw-material-receive', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'stock-issued', actions: ['view'] },
      { pageId: 'stock-received', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'raw-material-receive', actions: ['create', 'approve'] },
      { pageId: 'manufacturing', actions: ['issue_materials', 'edit_issued_stock'] },
      { pageId: 'stock-adjustment', actions: ['create', 'approve'] },
    ],
    edit: [{ pageId: 'stock-adjustment', actions: ['create', 'approve'] }],
    delete: [{ pageId: 'raw-material-receive', actions: ['delete'] }],
  },
  stock_cid_receipts: {
    read: [
      { pageId: 'stock-cid-receive', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'stock-received', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'stock-cid-receive', actions: ['create'] },
      { pageId: 'manufacturing', actions: ['receive_fg'] },
    ],
    edit: [{ pageId: 'stock-cid-receive', actions: ['approve'] }],
    delete: [{ pageId: 'stock-cid-receive', actions: ['delete'] }],
  },
  stock_cid_receipt_items: {
    read: [
      { pageId: 'stock-cid-receive', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
    ],
    create: [
      { pageId: 'stock-cid-receive', actions: ['create'] },
      { pageId: 'manufacturing', actions: ['receive_fg'] },
    ],
    edit: [{ pageId: 'stock-cid-receive', actions: ['approve'] }],
    delete: [{ pageId: 'stock-cid-receive', actions: ['delete'] }],
  },
  stock_inventory: {
    read: [
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'warehouse', actions: ['view'] },
      { pageId: 'stock-cid-receive', actions: ['view'] },
      { pageId: 'stock-transfer', actions: ['view'] },
      { pageId: 'stock-adjustment', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'stock-create-opening', actions: ['create', 'approve'] },
      { pageId: 'stock-upload-opening', actions: ['upload_excel', 'approve'] },
      { pageId: 'stock-upload-primary', actions: ['upload_excel', 'approve'] },
      { pageId: 'stock-cid-receive', actions: ['create', 'approve'] },
      { pageId: 'manufacturing', actions: ['receive_fg'] },
    ],
    edit: [
      { pageId: 'stock-create-opening', actions: ['edit', 'approve'] },
      { pageId: 'stock-adjustment', actions: ['create', 'approve'] },
      { pageId: 'stock-transfer', actions: ['approve', 'receive'] },
      { pageId: 'stock-primary-return', actions: ['create', 'approve'] },
      { pageId: 'stock-damage-return', actions: ['create', 'approve'] },
      { pageId: 'stock-cid-receive', actions: ['create', 'approve'] },
      { pageId: 'manufacturing', actions: ['receive_fg'] },
      { pageId: 'sales-orders', actions: ['dispatch_invoice', 'approve'] },
      { pageId: 'sales-orders-registry', actions: ['confirm', 'generate_do'] },
    ],
    delete: [{ pageId: 'stock-adjustment', actions: ['delete'] }],
  },
  stock_transfers: {
    read: [
      { pageId: 'stock-transfer', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'warehouse', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [{ pageId: 'stock-transfer', actions: ['create'] }],
    edit: [{ pageId: 'stock-transfer', actions: ['approve', 'receive'] }],
    delete: [{ pageId: 'stock-transfer', actions: ['cancel'] }],
  },
  stock_transfer_items: {
    read: [
      { pageId: 'stock-transfer', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'warehouse', actions: ['view'] },
    ],
    create: [{ pageId: 'stock-transfer', actions: ['create'] }],
    edit: [{ pageId: 'stock-transfer', actions: ['approve', 'receive'] }],
    delete: [{ pageId: 'stock-transfer', actions: ['cancel'] }],
  },

  // D. Manufacturing & Factory
  production_orders: {
    read: [
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'stock-cid-receive', actions: ['view'] },
      ...OVERTIME_READ_RULES,
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [{ pageId: 'manufacturing', actions: ['create_batch'] }],
    edit: [
      { pageId: 'manufacturing', actions: ['edit_batch', 'issue_materials', 'receive_fg'] },
      { pageId: 'manufacturing-costing', actions: ['allocate_cost', 'save_cost_sheet'] },
    ],
    delete: [{ pageId: 'manufacturing', actions: ['cancel_batch'] }],
  },
  bill_of_materials: {
    read: [
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'basic-data-products', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [{ pageId: 'manufacturing', actions: ['update_bom', 'view_bom_upload'] }],
    edit: [{ pageId: 'manufacturing', actions: ['update_bom', 'view_bom_upload'] }],
    delete: [{ pageId: 'manufacturing', actions: ['update_bom'] }],
  },
  bom_items: {
    read: [
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'basic-data-products', actions: ['view'] },
    ],
    create: [{ pageId: 'manufacturing', actions: ['update_bom', 'view_bom_upload'] }],
    edit: [{ pageId: 'manufacturing', actions: ['update_bom', 'view_bom_upload'] }],
    delete: [{ pageId: 'manufacturing', actions: ['update_bom'] }],
  },
  material_issues: {
    read: [
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [{ pageId: 'manufacturing', actions: ['issue_materials'] }],
    edit: [{ pageId: 'manufacturing', actions: ['edit_issued_stock', 'issue_materials'] }],
    delete: [{ pageId: 'manufacturing', actions: ['cancel_batch', 'edit_issued_stock'] }],
  },
  material_issue_items: {
    read: [
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
    ],
    create: [{ pageId: 'manufacturing', actions: ['issue_materials'] }],
    edit: [{ pageId: 'manufacturing', actions: ['edit_issued_stock', 'issue_materials'] }],
    delete: [{ pageId: 'manufacturing', actions: ['cancel_batch', 'edit_issued_stock'] }],
  },
  production_consumption: {
    read: [
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'raw-material-inventory', actions: ['view'] },
    ],
    create: [{ pageId: 'manufacturing', actions: ['issue_materials'] }],
    edit: [{ pageId: 'manufacturing', actions: ['edit_issued_stock', 'issue_materials'] }],
    delete: [{ pageId: 'manufacturing', actions: ['cancel_batch'] }],
  },
  finished_goods_receipts: {
    read: [
      { pageId: 'manufacturing', actions: ['view'] },
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'stock-cid-receive', actions: ['view'] },
      { pageId: 'inventory-stock', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'manufacturing', actions: ['receive_fg'] },
      { pageId: 'stock-cid-receive', actions: ['create'] },
    ],
    edit: [
      { pageId: 'manufacturing', actions: ['receive_fg'] },
      { pageId: 'stock-cid-receive', actions: ['approve'] },
    ],
    delete: [{ pageId: 'manufacturing', actions: ['cancel_batch'] }],
  },
  expense_entries: {
    read: [
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      ...FINANCE_READ_RULES,
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [{ pageId: 'manufacturing-costing', actions: ['post_expense'] }],
    edit: [{ pageId: 'manufacturing-costing', actions: ['approve_expense', 'allocate_cost'] }],
    delete: [{ pageId: 'manufacturing-costing', actions: ['rollback_allocation'] }],
  },
  production_costs: {
    read: [
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      ...FINANCE_READ_RULES,
    ],
    create: [{ pageId: 'manufacturing-costing', actions: ['save_cost_sheet', 'allocate_cost'] }],
    edit: [{ pageId: 'manufacturing-costing', actions: ['save_cost_sheet', 'allocate_cost'] }],
    delete: [{ pageId: 'manufacturing-costing', actions: ['rollback_allocation'] }],
  },
  production_cost_allocations: {
    read: [
      { pageId: 'manufacturing-costing', actions: ['view'] },
      { pageId: 'manufacturing', actions: ['view'] },
      ...FINANCE_READ_RULES,
    ],
    create: [{ pageId: 'manufacturing-costing', actions: ['allocate_cost'] }],
    edit: [{ pageId: 'manufacturing-costing', actions: ['allocate_cost'] }],
    delete: [{ pageId: 'manufacturing-costing', actions: ['rollback_allocation'] }],
  },

  // E. Sales, CRM & Installments
  sales_orders: {
    read: [
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'sales-orders-registry', actions: ['view'] },
      ...INSTALLMENT_READ_RULES,
      ...FINANCE_READ_RULES,
      { pageId: 'mobile-field', actions: ['view'] },
      { pageId: 'warranty', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
      { pageId: 'dashboard', actions: ['view'] },
    ],
    create: [
      { pageId: 'sales-orders', actions: ['create'] },
      { pageId: 'sales-orders-registry', actions: ['create'] },
      { pageId: 'mobile-field', actions: ['place_order'] },
      { pageId: 'installment', actions: ['create'] },
    ],
    edit: [
      { pageId: 'sales-orders', actions: ['edit', 'approve', 'dispatch_invoice'] },
      { pageId: 'sales-orders-registry', actions: ['edit', 'submit', 'confirm', 'reject', 'generate_do'] },
      { pageId: 'collection', actions: ['collect'] },
    ],
    delete: [
      { pageId: 'sales-orders', actions: ['cancel'] },
      { pageId: 'sales-orders-registry', actions: ['cancel'] },
    ],
  },
  crm_agreements: {
    read: [
      { pageId: 'crm-agreements', actions: ['view'] },
      { pageId: 'customers-crm', actions: ['view'] },
      { pageId: 'sales-orders', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [{ pageId: 'crm-agreements', actions: ['create'] }],
    edit: [{ pageId: 'crm-agreements', actions: ['edit', 'approve'] }],
    delete: [{ pageId: 'crm-agreements', actions: ['terminate'] }],
  },
  installment_plans: {
    read: INSTALLMENT_READ_RULES,
    create: INSTALLMENT_WRITE_RULES,
    edit: INSTALLMENT_WRITE_RULES,
    delete: [
      { pageId: 'installment', actions: ['delete'] },
      { pageId: 'installment-agreements', actions: ['delete'] },
    ],
  },
  installment_schedules: {
    read: INSTALLMENT_READ_RULES,
    create: INSTALLMENT_WRITE_RULES,
    edit: INSTALLMENT_WRITE_RULES,
    delete: [
      { pageId: 'installment', actions: ['delete'] },
      { pageId: 'installment-agreements', actions: ['delete'] },
    ],
  },
  installment_payments: {
    read: INSTALLMENT_READ_RULES,
    create: INSTALLMENT_WRITE_RULES,
    edit: INSTALLMENT_WRITE_RULES,
    delete: [{ pageId: 'installment', actions: ['delete'] }],
  },
  installment_notifications: {
    read: INSTALLMENT_READ_RULES,
    create: INSTALLMENT_WRITE_RULES,
    edit: INSTALLMENT_WRITE_RULES,
    delete: [{ pageId: 'installment', actions: ['delete'] }],
  },
  collection_assignments: {
    read: [
      { pageId: 'collection', actions: ['view'] },
      { pageId: 'collection-assignments', actions: ['view'] },
      { pageId: 'installment', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'collection', actions: ['create', 'assign', 'collect'] },
      { pageId: 'collection-assignments', actions: ['create', 'assign'] },
    ],
    edit: [
      { pageId: 'collection', actions: ['edit', 'assign', 'collect'] },
      { pageId: 'collection-assignments', actions: ['edit', 'assign'] },
    ],
    delete: [{ pageId: 'collection', actions: ['delete'] }],
  },
  collection_followups: {
    read: [
      { pageId: 'collection', actions: ['view'] },
      { pageId: 'collection-followups', actions: ['view'] },
      { pageId: 'installment', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'collection', actions: ['create', 'collect'] },
      { pageId: 'collection-followups', actions: ['create'] },
    ],
    edit: [
      { pageId: 'collection', actions: ['edit', 'collect'] },
      { pageId: 'collection-followups', actions: ['edit'] },
    ],
    delete: [{ pageId: 'collection', actions: ['delete'] }],
  },

  // F. Accounts & Finance
  chart_of_accounts: {
    read: FINANCE_READ_RULES,
    create: FINANCE_WRITE_RULES,
    edit: FINANCE_WRITE_RULES,
    delete: FINANCE_WRITE_RULES,
  },
  financial_years: {
    read: FINANCE_READ_RULES,
    create: FINANCE_WRITE_RULES,
    edit: FINANCE_WRITE_RULES,
    delete: FINANCE_WRITE_RULES,
  },
  accounting_periods: {
    read: FINANCE_READ_RULES,
    create: FINANCE_WRITE_RULES,
    edit: FINANCE_WRITE_RULES,
    delete: FINANCE_WRITE_RULES,
  },
  accounting_vouchers: {
    read: FINANCE_READ_RULES,
    create: FINANCE_WRITE_RULES,
    edit: FINANCE_WRITE_RULES,
    delete: [{ pageId: 'finance-cashbook', actions: ['reverse_voucher'] }],
  },
  accounting_voucher_lines: {
    read: FINANCE_READ_RULES,
    create: FINANCE_WRITE_RULES,
    edit: FINANCE_WRITE_RULES,
    delete: [{ pageId: 'finance-cashbook', actions: ['reverse_voucher'] }],
  },
  general_ledger_entries: {
    read: FINANCE_READ_RULES,
    create: FINANCE_WRITE_RULES,
    edit: FINANCE_WRITE_RULES,
    delete: [{ pageId: 'finance-cashbook', actions: ['reverse_voucher'] }],
  },

  // G. HR, Attendance & Overtime
  employee_attendances: {
    read: [
      { pageId: 'payroll', actions: ['view'] },
      { pageId: 'mobile-field', actions: ['view'] },
      ...OVERTIME_READ_RULES,
      { pageId: 'field-tracker', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'payroll', actions: ['create'] },
      { pageId: 'mobile-field', actions: ['checkin'] },
    ],
    edit: [{ pageId: 'payroll', actions: ['edit'] }],
    delete: [{ pageId: 'payroll', actions: ['delete'] }],
  },
  attendance_rejected_attempts: {
    read: [
      { pageId: 'payroll', actions: ['view'] },
      { pageId: 'field-tracker', actions: ['view'] },
      { pageId: 'reports', actions: ['view'] },
    ],
    create: [
      { pageId: 'mobile-field', actions: ['checkin'] },
      { pageId: 'payroll', actions: ['create'] },
    ],
    edit: [{ pageId: 'payroll', actions: ['edit'] }],
    delete: [{ pageId: 'payroll', actions: ['delete'] }],
  },
  employee_overtimes: {
    read: OVERTIME_READ_RULES,
    create: [
      { pageId: 'overtime-management', actions: ['create_request', 'record_attendance'] },
      { pageId: 'payroll', actions: ['create'] },
    ],
    edit: [
      { pageId: 'overtime-management', actions: ['edit_request', 'approve_final'] },
      { pageId: 'payroll', actions: ['edit'] },
    ],
    delete: [
      { pageId: 'overtime-management', actions: ['edit_request', 'approve_final'] },
      { pageId: 'payroll', actions: ['delete'] },
    ],
  },
  overtime_requests: {
    read: OVERTIME_READ_RULES,
    create: [{ pageId: 'overtime-management', actions: ['create_request'] }],
    edit: [
      {
        pageId: 'overtime-management',
        actions: [
          'edit_request',
          'approve_supervisor',
          'approve_production',
          'verify_hr_accounts',
          'approve_final',
          'allocate_batch',
          'sync_payroll_costing',
        ],
      },
    ],
    delete: [{ pageId: 'overtime-management', actions: ['edit_request', 'approve_final'] }],
  },
  overtime_batch_allocations: {
    read: OVERTIME_READ_RULES,
    create: [{ pageId: 'overtime-management', actions: ['create_request', 'allocate_batch'] }],
    edit: [{ pageId: 'overtime-management', actions: ['edit_request', 'allocate_batch'] }],
    delete: [{ pageId: 'overtime-management', actions: ['edit_request', 'allocate_batch', 'approve_final'] }],
  },
  overtime_attendances: {
    read: OVERTIME_READ_RULES,
    create: [{ pageId: 'overtime-management', actions: ['record_attendance'] }],
    edit: [{ pageId: 'overtime-management', actions: ['record_attendance', 'verify_attendance'] }],
    delete: [{ pageId: 'overtime-management', actions: ['edit_request', 'approve_final'] }],
  },
  overtime_policies: {
    read: OVERTIME_READ_RULES,
    create: [{ pageId: 'overtime-management', actions: ['configure_policy'] }],
    edit: [{ pageId: 'overtime-management', actions: ['configure_policy'] }],
    delete: [{ pageId: 'overtime-management', actions: ['configure_policy'] }],
  },
  overtime_audit_logs: {
    read: OVERTIME_READ_RULES,
    create: [
      {
        pageId: 'overtime-management',
        actions: [
          'create_request',
          'edit_request',
          'approve_supervisor',
          'approve_production',
          'verify_hr_accounts',
          'approve_final',
          'record_attendance',
          'verify_attendance',
          'allocate_batch',
          'sync_payroll_costing',
          'configure_policy',
        ],
      },
    ],
    edit: [{ pageId: 'overtime-management', actions: ['configure_policy'] }],
    delete: [{ pageId: 'overtime-management', actions: ['approve_final'] }],
  },
};

function matchesAnyRule(user: AuthenticatedErpUser, rules: PageActionRule[]): boolean {
  if (!user) return false;
  if (user.role === 'Super Admin') return true;
  for (const rule of rules) {
    for (const action of rule.actions) {
      if (hasPageAction(user, rule.pageId, action)) {
        return true;
      }
    }
  }
  return false;
}

export function authorizeTableOperation(
  user: AuthenticatedErpUser,
  table: string,
  operation: OperationType
): { allowed: boolean; reason?: string } {
  const rule = TABLE_RBAC_CONFIG[table];
  if (!rule) {
    return { allowed: false, reason: `Unknown or non-permitted ERP table "${table}".` };
  }
  if (user.role === 'Super Admin') {
    return { allowed: true };
  }

  let requiredRules: PageActionRule[];
  if (operation === 'select') requiredRules = rule.read;
  else if (operation === 'insert') requiredRules = rule.create;
  else if (operation === 'upsert') requiredRules = [...rule.create, ...rule.edit];
  else if (operation === 'update') requiredRules = rule.edit;
  else requiredRules = rule.delete;

  if (matchesAnyRule(user, requiredRules)) {
    return { allowed: true };
  }

  return {
    allowed: false,
    reason: `Forbidden: Your account lacks required "${operation}" permission for "${table}".`,
  };
}

const ALLOWED_SELECT_EXPRESSIONS = new Set([
  '*',
  '*, stock_cid_receipt_items(*)',
  '*, stock_transfer_items(*)',
  '*, accounting_periods(*)',
  '*, accounting_voucher_lines(*)',
]);

function sanitizeSelectExpr(table: string, selectExpr?: string): string {
  if (!selectExpr || !selectExpr.trim()) return '*';
  const trimmed = selectExpr.trim();
  if (ALLOWED_SELECT_EXPRESSIONS.has(trimmed)) {
    return trimmed;
  }
  // Safe comma-separated column names (excluding password on users)
  const cols = trimmed
    .split(',')
    .map((c) => c.trim())
    .filter((c) => /^[a-zA-Z0-9_]+$/.test(c));
  if (cols.length === 0) return '*';
  const safeCols = table === 'users' ? cols.filter((c) => c.toLowerCase() !== 'password' && c.toLowerCase() !== 'password_hash') : cols;
  return safeCols.length > 0 ? safeCols.join(', ') : 'id';
}

function sanitizeRowForCaller(table: string, row: any, caller: AuthenticatedErpUser): any {
  if (!row || typeof row !== 'object') return row;
  if (table === 'users') {
    const { password: _p, password_hash: _ph, ...safe } = row;
    return safe;
  }
  if (table === 'production_orders') {
    return sanitizeProductionOrderForUser(row, caller);
  }
  if (table === 'overtime_requests' || table === 'overtime_batch_allocations' || table === 'employee_overtimes') {
    const perms = resolveOvertimePermissions(caller);
    if (!perms.viewCost) {
      return sanitizeOvertimeRecordForUser(row, caller);
    }
  }
  if (table === 'raw_materials') {
    const canSeeRates =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'raw-material-inventory', 'view_raw_material_purchase_rate') ||
      hasPageAction(caller, 'raw-material-inventory', 'view_raw_material_stock_value') ||
      hasPageAction(caller, 'raw-material-receive', 'create') ||
      hasPageAction(caller, 'procurement', 'view') ||
      hasPageAction(caller, 'manufacturing', 'view_batch_rate') ||
      hasPageAction(caller, 'manufacturing', 'update_bom');
    if (!canSeeRates) {
      const copy = { ...row };
      delete copy.last_purchase_unit_cost_bdt;
      delete copy.standard_cost_bdt;
      return copy;
    }
  }
  return row;
}

async function prepareWritePayload(table: string, payload: any): Promise<any> {
  const processSingle = async (item: any) => {
    if (!item || typeof item !== 'object') return item;
    const copy = { ...item };
    if (table === 'users') {
      if (copy.password !== undefined && copy.password !== null && String(copy.password).trim() !== '') {
        const rawPass = String(copy.password).trim();
        copy.password = isBcryptHash(rawPass) ? rawPass : await hashPassword(rawPass);
      } else if (copy.password === '') {
        delete copy.password;
      }
    }
    return copy;
  };

  if (Array.isArray(payload)) {
    return Promise.all(payload.map(processSingle));
  }
  return processSingle(payload);
}

interface QueryFilter {
  type: 'eq' | 'neq' | 'in' | 'ilike' | 'gte' | 'or';
  column?: string;
  value?: any;
  expr?: string;
}

function applyFilters(query: any, filters: QueryFilter[]) {
  let q = query;
  for (const f of filters) {
    if (f.type === 'eq' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.eq(f.column, f.value);
    } else if (f.type === 'neq' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.neq(f.column, f.value);
    } else if (f.type === 'in' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column) && Array.isArray(f.value)) {
      q = q.in(f.column, f.value);
    } else if (f.type === 'ilike' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.ilike(f.column, f.value);
    } else if (f.type === 'gte' && f.column && /^[a-zA-Z0-9_]+$/.test(f.column)) {
      q = q.gte(f.column, f.value);
    } else if (f.type === 'or' && typeof f.expr === 'string' && f.expr.trim().length > 0 && f.expr.length < 400) {
      // Allow only safe PostgREST eq/ilike clause lists (no nested injection)
      const parts = f.expr.split(',').map((p) => p.trim());
      const allSafe = parts.every((p) => /^[a-zA-Z0-9_]+\.(eq|ilike)\.[^\s;]+$/.test(p));
      if (allSafe) {
        q = q.or(f.expr.trim());
      }
    }
  }
  return q;
}

function stripMissingColumnFromPayload(payload: any, errMessage: string): boolean {
  const match =
    errMessage.match(/column ["']?([a-zA-Z0-9_]+)["']? of relation/i) ||
    errMessage.match(/Could not find the ['"]?([a-zA-Z0-9_]+)['"]? column/i);
  if (!match || !match[1]) return false;
  const col = match[1];
  let removed = false;
  const items = Array.isArray(payload) ? payload : [payload];
  for (const item of items) {
    if (item && typeof item === 'object' && col in item) {
      delete item[col];
      removed = true;
    }
  }
  return removed;
}

export function registerErpGatewayRoutes(app: express.Application) {
  // --------------------------------------------------------------------------
  // Centralized Authenticated & RBAC-Protected Database Gateway for 58 Tables
  // --------------------------------------------------------------------------
  app.post('/api/erp/db/:table', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({
        data: null,
        error: {
          message: 'Authentication required. Please sign in to Ensec ERP.',
          code: 'UNAUTHORIZED',
          status: 401,
        },
      });
    }

    const table = String(req.params.table || '').trim();
    const body = req.body || {};
    const operation: OperationType = (['select', 'insert', 'upsert', 'update', 'delete'].includes(body.operation)
      ? body.operation
      : 'select') as OperationType;

    const auth = authorizeTableOperation(caller, table, operation);
    if (!auth.allowed) {
      return res.status(403).json({
        data: null,
        error: {
          message: auth.reason || `Forbidden: Access denied to "${table}" (${operation}).`,
          code: '42501',
          status: 403,
        },
      });
    }

    const db = getServerSupabase();
    if (!db) {
      return res.status(503).json({
        data: null,
        error: {
          message: 'Server database connection is not configured.',
          code: 'DB_NOT_CONFIGURED',
          status: 503,
        },
      });
    }

    try {
      const filters: QueryFilter[] = Array.isArray(body.filters) ? body.filters : [];
      const orders: Array<{ column: string; ascending?: boolean }> = Array.isArray(body.orders) ? body.orders : [];
      const limit = typeof body.limit === 'number' && body.limit > 0 ? Math.min(body.limit, 5000) : undefined;
      const returnRows = Boolean(body.returnSelect) || operation === 'select';
      const selectExpr = sanitizeSelectExpr(table, body.select);

      if (operation === 'select') {
        let q: any = db.from(table).select(selectExpr);
        q = applyFilters(q, filters);
        for (const ord of orders) {
          if (ord.column && /^[a-zA-Z0-9_]+$/.test(ord.column)) {
            q = q.order(ord.column, { ascending: ord.ascending !== false });
          }
        }
        if (limit) q = q.limit(limit);
        if (body.single) q = q.single();
        else if (body.maybeSingle) q = q.maybeSingle();

        const { data, error } = await q;
        if (error) {
          return res.status(400).json({
            data: null,
            error: {
              message: sanitizeDatabaseError(error.message),
              code: error.code || 'DB_ERROR',
            },
          });
        }
        const sanitized = Array.isArray(data)
          ? data.map((row) => sanitizeRowForCaller(table, row, caller))
          : data
          ? sanitizeRowForCaller(table, data, caller)
          : data;
        return res.status(200).json({ data: sanitized, error: null });
      }

      if (operation === 'insert' || operation === 'upsert' || operation === 'update') {
        let payload = await prepareWritePayload(table, body.payload);
        let resultData: any = null;
        let lastErr: any = null;

        for (let attempt = 0; attempt < 8; attempt++) {
          let q: any;
          if (operation === 'insert') {
            q = db.from(table).insert(payload);
          } else if (operation === 'upsert') {
            const upsertOpts: any = {};
            if (body.options?.onConflict && /^[a-zA-Z0-9_,]+$/.test(String(body.options.onConflict))) {
              upsertOpts.onConflict = String(body.options.onConflict);
            }
            if (body.options?.ignoreDuplicates !== undefined) {
              upsertOpts.ignoreDuplicates = Boolean(body.options.ignoreDuplicates);
            }
            q = db.from(table).upsert(payload, Object.keys(upsertOpts).length > 0 ? upsertOpts : undefined);
          } else {
            q = db.from(table).update(payload);
            q = applyFilters(q, filters);
          }

          if (returnRows) {
            q = q.select(selectExpr === '*' ? undefined : selectExpr);
            if (body.single) q = q.single();
            else if (body.maybeSingle) q = q.maybeSingle();
          }

          const { data, error } = await q;
          if (!error) {
            resultData = data;
            lastErr = null;
            break;
          }
          lastErr = error;
          const stripped = stripMissingColumnFromPayload(payload, error.message || '');
          if (stripped) continue;
          break;
        }

        if (lastErr) {
          return res.status(400).json({
            data: null,
            error: {
              message: sanitizeDatabaseError(lastErr.message),
              code: lastErr.code || 'DB_WRITE_ERROR',
            },
          });
        }

        const sanitized = Array.isArray(resultData)
          ? resultData.map((row) => sanitizeRowForCaller(table, row, caller))
          : resultData
          ? sanitizeRowForCaller(table, resultData, caller)
          : resultData;

        const firstRow = Array.isArray(sanitized) ? sanitized[0] : sanitized || (Array.isArray(payload) ? payload[0] : payload);
        emitErpTableEvent({
          table,
          eventType: operation === 'update' ? 'UPDATE' : 'INSERT',
          newRow: firstRow || null,
        });

        return res.status(200).json({ data: sanitized ?? null, error: null });
      }

      if (operation === 'delete') {
        let q: any = db.from(table).delete();
        q = applyFilters(q, filters);
        if (returnRows) q = q.select();
        const { data, error } = await q;
        if (error) {
          return res.status(400).json({
            data: null,
            error: {
              message: sanitizeDatabaseError(error.message),
              code: error.code || 'DB_DELETE_ERROR',
            },
          });
        }

        const deletedFirst = Array.isArray(data) ? data[0] : data;
        emitErpTableEvent({
          table,
          eventType: 'DELETE',
          oldRow: deletedFirst || null,
        });

        return res.status(200).json({ data: data ?? null, error: null });
      }

      return res.status(400).json({ data: null, error: { message: 'Unsupported database operation.' } });
    } catch (err: any) {
      return res.status(500).json({
        data: null,
        error: {
          message: sanitizeDatabaseError(err?.message || 'Internal database gateway error.'),
          code: 'GATEWAY_ERROR',
        },
      });
    }
  });

  // --------------------------------------------------------------------------
  // Dedicated User Management Endpoints (Always bcrypt-hashed, never expose passwords)
  // --------------------------------------------------------------------------
  app.get('/api/erp/users', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ ok: false, error: 'Authentication required.' });
    }
    if (caller.role !== 'Super Admin' && !hasPageAction(caller, 'users-permissions', 'view')) {
      return res.status(403).json({
        ok: false,
        code: 'USERS_FORBIDDEN',
        error: 'Forbidden: User Management view permission required.',
      });
    }

    const db = getServerSupabase();
    if (db) {
      try {
        const { data, error } = await db.from('users').select('*').order('id', { ascending: true });
        if (!error && Array.isArray(data)) {
          const users = data.map((row) => mapSupabaseUserRowSafe(row));
          users.forEach((u) => indexUserInAuthCache(u));
          return res.json({ ok: true, users });
        }
      } catch (err: any) {
        return res.status(500).json({ ok: false, error: sanitizeDatabaseError(err?.message) });
      }
    }

    return res.status(200).json({ ok: true, users: [], dbConfigured: false });
  });

  app.put('/api/erp/users/:id/password', async (req, res) => {
    const caller = await resolveRequestUser(req);
    if (!caller) {
      return res.status(401).json({ success: false, error: 'Authentication required.' });
    }

    const targetId = String(req.params.id || '').trim();
    const isSelf =
      caller.id === targetId ||
      caller.userId.toLowerCase() === targetId.toLowerCase() ||
      (caller.email && caller.email.toLowerCase() === targetId.toLowerCase());

    const canAdminReset =
      caller.role === 'Super Admin' ||
      hasPageAction(caller, 'users-permissions', 'reset_password') ||
      hasPageAction(caller, 'users-permissions', 'edit');

    if (!isSelf && !canAdminReset) {
      return res.status(403).json({
        success: false,
        code: 'PASSWORD_RESET_FORBIDDEN',
        error: 'Forbidden: You do not have permission to reset another user password.',
      });
    }

    const cleanPassword = String(req.body?.newPassword || req.body?.password || '').trim();
    if (!cleanPassword || cleanPassword.length < 4) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 4 characters long.',
      });
    }

    const passwordHash = await hashPassword(cleanPassword);
    const db = getServerSupabase();
    if (!db) {
      return res.status(200).json({
        success: true,
        warning: 'Database is not configured on the server; updated server session cache only.',
      });
    }

    try {
      const targetEmail = req.body?.email ? String(req.body.email).trim().toLowerCase() : '';
      const targetUid = req.body?.userId ? String(req.body.userId).trim() : targetId;
      let existingSbUser: any = null;

      if (targetEmail) {
        const { data } = await db.from('users').select('id, email, name').ilike('email', targetEmail).limit(1);
        if (Array.isArray(data) && data.length > 0) existingSbUser = data[0];
      }
      if (!existingSbUser && targetUid) {
        const { data } = await db.from('users').select('id, email, name').eq('uid', targetUid).limit(1);
        if (Array.isArray(data) && data.length > 0) existingSbUser = data[0];
      }
      if (!existingSbUser && /^u-sb-(\d+)$/i.test(targetId)) {
        const numId = Number(targetId.replace(/^u-sb-/i, ''));
        const { data } = await db.from('users').select('id, email, name').eq('id', numId).limit(1);
        if (Array.isArray(data) && data.length > 0) existingSbUser = data[0];
      }

      if (existingSbUser) {
        const updatePayload: any = {
          password: passwordHash,
          updated_at: new Date().toISOString(),
        };
        let lastErr: any = null;
        for (let attempt = 0; attempt < 4; attempt++) {
          const { error } = await db.from('users').update(updatePayload).eq('id', existingSbUser.id);
          if (!error) {
            lastErr = null;
            break;
          }
          lastErr = error;
          if (!stripMissingColumnFromPayload(updatePayload, error.message || '')) break;
        }
        if (lastErr) {
          return res.status(400).json({
            success: false,
            error: sanitizeDatabaseError(lastErr.message),
          });
        }
        return res.status(200).json({ success: true });
      }

      // Create missing user row with hashed password if not yet persisted
      const insertPayload: any = {
        name: req.body?.name || 'Ensec Staff',
        email: targetEmail || `${targetUid.toLowerCase()}@ensecbd.com`,
        password: passwordHash,
        phone: req.body?.phone || null,
        role: req.body?.role || 'Field Force',
        designation: req.body?.designation || null,
        department: req.body?.department || 'Operations',
        status: req.body?.status || 'Active',
        uid: targetUid,
        permissions: req.body?.permissions || {},
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      let lastInsErr: any = null;
      for (let attempt = 0; attempt < 8; attempt++) {
        const { error } = await db.from('users').upsert(insertPayload, { onConflict: 'email' });
        if (!error) {
          lastInsErr = null;
          break;
        }
        lastInsErr = error;
        if (!stripMissingColumnFromPayload(insertPayload, error.message || '')) break;
      }
      if (lastInsErr) {
        return res.status(400).json({
          success: false,
          error: sanitizeDatabaseError(lastInsErr.message),
        });
      }
      return res.status(200).json({ success: true });
    } catch (err: any) {
      return res.status(500).json({
        success: false,
        error: sanitizeDatabaseError(err?.message || 'Failed to update password.'),
      });
    }
  });
}
