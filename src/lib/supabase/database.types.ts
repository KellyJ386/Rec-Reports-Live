/**
 * Database types for the Rec Reports Supabase project (schema `public`).
 *
 * Produced by a one-off generator that reads information_schema.columns,
 * pg_proc, pg_enum and pg_constraint from a local Postgres built by
 * scripts/db/test-local.sh from supabase/migrations/. It is NOT output of the
 * Supabase CLI (`supabase gen types typescript`) and it was not produced by
 * @supabase/postgres-meta. Regenerate after every migration (the CLI command
 * against the migrated database is the source of truth once it is available),
 * and never edit by hand.
 */
export type Json =
  | string
  | number
  | boolean
  | null
  | { [key: string]: Json | undefined }
  | Json[];

export type Database = {
  public: {
    Tables: {
      accounts: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          user_id: string
          disabled_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          user_id: string
          disabled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          user_id?: string
          disabled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "accounts_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "accounts_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      acknowledgments: {
        Row: {
          id: string
          organization_id: string
          notice_id: string
          person_id: string
          acknowledged_at: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          notice_id: string
          person_id: string
          acknowledged_at?: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          notice_id?: string
          person_id?: string
          acknowledged_at?: string
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "acknowledgments_notice_id_organization_id_fkey"
            columns: ["notice_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "notices"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "acknowledgments_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "acknowledgments_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      audit_log: {
        Row: {
          id: number
          occurred_at: string
          transaction_id: number
          organization_id: string | null
          location_id: string | null
          actor_user_id: string | null
          actor_person_id: string | null
          actor_role: string
          action: string
          table_schema: string
          table_name: string
          row_id: string | null
          old_row: Json | null
          new_row: Json | null
          changed_columns: string[] | null
        }
        Insert: {
          id?: number
          occurred_at?: string
          transaction_id?: number
          organization_id?: string | null
          location_id?: string | null
          actor_user_id?: string | null
          actor_person_id?: string | null
          actor_role: string
          action: string
          table_schema: string
          table_name: string
          row_id?: string | null
          old_row?: Json | null
          new_row?: Json | null
          changed_columns?: string[] | null
        }
        Update: {
          id?: number
          occurred_at?: string
          transaction_id?: number
          organization_id?: string | null
          location_id?: string | null
          actor_user_id?: string | null
          actor_person_id?: string | null
          actor_role?: string
          action?: string
          table_schema?: string
          table_name?: string
          row_id?: string | null
          old_row?: Json | null
          new_row?: Json | null
          changed_columns?: string[] | null
        }
        Relationships: [
        ]
      }
      availability: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          day_of_week: number
          start_time: string
          end_time: string
          kind: string
          effective_from: string | null
          effective_to: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          day_of_week: number
          start_time: string
          end_time: string
          kind: string
          effective_from?: string | null
          effective_to?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          day_of_week?: number
          start_time?: string
          end_time?: string
          kind?: string
          effective_from?: string | null
          effective_to?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "availability_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "availability_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      job_titles: {
        Row: {
          id: string
          organization_id: string
          name: string
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          name: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          name?: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "job_titles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      locations: {
        Row: {
          id: string
          organization_id: string
          name: string
          code: string | null
          timezone: string
          address: string | null
          phone: string | null
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          name: string
          code?: string | null
          timezone: string
          address?: string | null
          phone?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          name?: string
          code?: string | null
          timezone?: string
          address?: string | null
          phone?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "locations_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      message_recipients: {
        Row: {
          id: string
          organization_id: string
          message_id: string
          person_id: string
          read_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          message_id: string
          person_id: string
          read_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          message_id?: string
          person_id?: string
          read_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "message_recipients_message_id_organization_id_fkey"
            columns: ["message_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "messages"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "message_recipients_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "message_recipients_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      messages: {
        Row: {
          id: string
          organization_id: string
          sender_person_id: string
          body: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          sender_person_id: string
          body: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          sender_person_id?: string
          body?: string
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "messages_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "messages_sender_person_id_organization_id_fkey"
            columns: ["sender_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      modules: {
        Row: {
          key: string
          name: string
          sort_order: number
          created_at: string
          updated_at: string
        }
        Insert: {
          key: string
          name: string
          sort_order?: number
          created_at?: string
          updated_at?: string
        }
        Update: {
          key?: string
          name?: string
          sort_order?: number
          created_at?: string
          updated_at?: string
        }
        Relationships: [
        ]
      }
      notice_audiences: {
        Row: {
          id: string
          organization_id: string
          notice_id: string
          location_id: string | null
          job_title_id: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          notice_id: string
          location_id?: string | null
          job_title_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          notice_id?: string
          location_id?: string | null
          job_title_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "notice_audiences_job_title_id_organization_id_fkey"
            columns: ["job_title_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "job_titles"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "notice_audiences_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "notice_audiences_notice_id_organization_id_fkey"
            columns: ["notice_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "notices"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "notice_audiences_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      notices: {
        Row: {
          id: string
          organization_id: string
          location_id: string | null
          title: string
          body: string
          urgency: string
          requires_acknowledgment: boolean
          publish_at: string | null
          expires_at: string | null
          status: string
          author_person_id: string | null
          published_at: string | null
          published_by_person_id: string | null
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id?: string | null
          title: string
          body: string
          urgency?: string
          requires_acknowledgment?: boolean
          publish_at?: string | null
          expires_at?: string | null
          status?: string
          author_person_id?: string | null
          published_at?: string | null
          published_by_person_id?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string | null
          title?: string
          body?: string
          urgency?: string
          requires_acknowledgment?: boolean
          publish_at?: string | null
          expires_at?: string | null
          status?: string
          author_person_id?: string | null
          published_at?: string | null
          published_by_person_id?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "notices_author_person_id_organization_id_fkey"
            columns: ["author_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "notices_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "notices_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "notices_published_by_person_id_organization_id_fkey"
            columns: ["published_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      notification_deliveries: {
        Row: {
          id: string
          organization_id: string
          notification_id: string
          person_id: string
          channel: string
          status: string
          attempts: number
          next_attempt_at: string
          locked_at: string | null
          locked_by: string | null
          lock_expires_at: string | null
          provider_message_id: string | null
          last_error: string | null
          sent_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          notification_id: string
          person_id: string
          channel: string
          status?: string
          attempts?: number
          next_attempt_at?: string
          locked_at?: string | null
          locked_by?: string | null
          lock_expires_at?: string | null
          provider_message_id?: string | null
          last_error?: string | null
          sent_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          notification_id?: string
          person_id?: string
          channel?: string
          status?: string
          attempts?: number
          next_attempt_at?: string
          locked_at?: string | null
          locked_by?: string | null
          lock_expires_at?: string | null
          provider_message_id?: string | null
          last_error?: string | null
          sent_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "notification_deliveries_notification_id_organization_id_fkey"
            columns: ["notification_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "notifications"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "notification_deliveries_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "notification_deliveries_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      notification_preferences: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          channel: string
          enabled: boolean
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          channel: string
          enabled?: boolean
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          channel?: string
          enabled?: boolean
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "notification_preferences_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "notification_preferences_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      notifications: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          kind: string
          title: string
          body: string | null
          link_path: string | null
          source_table: string | null
          source_id: string | null
          source_event_id: string
          urgency: string
          read_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          kind: string
          title: string
          body?: string | null
          link_path?: string | null
          source_table?: string | null
          source_id?: string | null
          source_event_id: string
          urgency?: string
          read_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          kind?: string
          title?: string
          body?: string | null
          link_path?: string | null
          source_table?: string | null
          source_id?: string | null
          source_event_id?: string
          urgency?: string
          read_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "notifications_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "notifications_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      organization_settings: {
        Row: {
          id: string
          organization_id: string
          default_timezone: string
          week_starts_on: number
          settings: Json
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          default_timezone?: string
          week_starts_on?: number
          settings?: Json
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          default_timezone?: string
          week_starts_on?: number
          settings?: Json
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "organization_settings_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      organizations: {
        Row: {
          id: string
          name: string
          slug: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          name: string
          slug: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          name?: string
          slug?: string
          created_at?: string
          updated_at?: string
        }
        Relationships: [
        ]
      }
      outbox_event_handlers: {
        Row: {
          event_id: string
          handler: string
          organization_id: string
          completed_at: string
          created_at: string
          updated_at: string
        }
        Insert: {
          event_id: string
          handler: string
          organization_id: string
          completed_at?: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          event_id?: string
          handler?: string
          organization_id?: string
          completed_at?: string
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "outbox_event_handlers_event_id_organization_id_fkey"
            columns: ["event_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "outbox_events"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "outbox_event_handlers_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      outbox_events: {
        Row: {
          id: string
          organization_id: string
          location_id: string | null
          type: string
          schema_version: number
          entity_table: string
          entity_id: string
          payload: Json
          correlation_id: string
          status: string
          attempts: number
          next_attempt_at: string
          locked_at: string | null
          locked_by: string | null
          lock_expires_at: string | null
          last_error: string | null
          processed_at: string | null
          retried_at: string | null
          retried_by_person_id: string | null
          created_at: string
          updated_at: string
          causation_id: string | null
          causation_depth: number
          manual_retries: number
        }
        Insert: {
          id?: string
          organization_id: string
          location_id?: string | null
          type: string
          schema_version?: number
          entity_table: string
          entity_id: string
          payload?: Json
          correlation_id: string
          status?: string
          attempts?: number
          next_attempt_at?: string
          locked_at?: string | null
          locked_by?: string | null
          lock_expires_at?: string | null
          last_error?: string | null
          processed_at?: string | null
          retried_at?: string | null
          retried_by_person_id?: string | null
          created_at?: string
          updated_at?: string
          causation_id?: string | null
          causation_depth?: number
          manual_retries?: number
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string | null
          type?: string
          schema_version?: number
          entity_table?: string
          entity_id?: string
          payload?: Json
          correlation_id?: string
          status?: string
          attempts?: number
          next_attempt_at?: string
          locked_at?: string | null
          locked_by?: string | null
          lock_expires_at?: string | null
          last_error?: string | null
          processed_at?: string | null
          retried_at?: string | null
          retried_by_person_id?: string | null
          created_at?: string
          updated_at?: string
          causation_id?: string | null
          causation_depth?: number
          manual_retries?: number
        }
        Relationships: [
          {
            foreignKeyName: "outbox_events_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "outbox_events_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "outbox_events_retried_by_person_id_organization_id_fkey"
            columns: ["retried_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      people: {
        Row: {
          id: string
          organization_id: string
          first_name: string
          last_name: string
          preferred_name: string | null
          email: string | null
          phone: string | null
          employee_number: string | null
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          first_name: string
          last_name: string
          preferred_name?: string | null
          email?: string | null
          phone?: string | null
          employee_number?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          first_name?: string
          last_name?: string
          preferred_name?: string | null
          email?: string | null
          phone?: string | null
          employee_number?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "people_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      person_job_titles: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          job_title_id: string
          location_id: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          job_title_id: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          job_title_id?: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "person_job_titles_job_title_id_organization_id_fkey"
            columns: ["job_title_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "job_titles"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "person_job_titles_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "person_job_titles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "person_job_titles_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      person_qualifications: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          qualification_id: string
          valid_from: string | null
          expires_on: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          qualification_id: string
          valid_from?: string | null
          expires_on?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          qualification_id?: string
          valid_from?: string | null
          expires_on?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "person_qualifications_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "person_qualifications_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "person_qualifications_qualification_id_organization_id_fkey"
            columns: ["qualification_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "qualifications"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      platform_admins: {
        Row: {
          user_id: string
          note: string | null
          created_at: string
        }
        Insert: {
          user_id: string
          note?: string | null
          created_at?: string
        }
        Update: {
          user_id?: string
          note?: string | null
          created_at?: string
        }
        Relationships: [
        ]
      }
      position_qualifications: {
        Row: {
          id: string
          organization_id: string
          position_id: string
          qualification_id: string
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          position_id: string
          qualification_id: string
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          position_id?: string
          qualification_id?: string
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "position_qualifications_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "position_qualifications_position_id_organization_id_fkey"
            columns: ["position_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "positions"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "position_qualifications_qualification_id_organization_id_fkey"
            columns: ["qualification_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "qualifications"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      positions: {
        Row: {
          id: string
          organization_id: string
          location_id: string | null
          name: string
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id?: string | null
          name: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string | null
          name?: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "positions_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "positions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      push_subscriptions: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          endpoint: string
          p256dh: string
          auth_secret: string
          user_agent: string | null
          last_used_at: string | null
          disabled_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          endpoint: string
          p256dh: string
          auth_secret: string
          user_agent?: string | null
          last_used_at?: string | null
          disabled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          endpoint?: string
          p256dh?: string
          auth_secret?: string
          user_agent?: string | null
          last_used_at?: string | null
          disabled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "push_subscriptions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "push_subscriptions_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      qualifications: {
        Row: {
          id: string
          organization_id: string
          name: string
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          name: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          name?: string
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "qualifications_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      role_assignments: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          role_id: string
          location_id: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          role_id: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          role_id?: string
          location_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "role_assignments_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "role_assignments_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "role_assignments_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "role_assignments_role_id_fkey"
            columns: ["role_id"]
            isOneToOne: false
            referencedRelation: "roles"
            referencedColumns: ["id"]
          },
        ]
      }
      role_default_permissions: {
        Row: {
          id: string
          organization_id: string | null
          role_id: string
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id?: string | null
          role_id: string
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string | null
          role_id?: string
          module_key?: string
          level?: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "role_default_permissions_module_key_fkey"
            columns: ["module_key"]
            isOneToOne: false
            referencedRelation: "modules"
            referencedColumns: ["key"]
          },
          {
            foreignKeyName: "role_default_permissions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "role_default_permissions_role_id_fkey"
            columns: ["role_id"]
            isOneToOne: false
            referencedRelation: "roles"
            referencedColumns: ["id"]
          },
        ]
      }
      roles: {
        Row: {
          id: string
          organization_id: string | null
          key: string
          name: string
          description: string | null
          rank: number
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id?: string | null
          key: string
          name: string
          description?: string | null
          rank: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string | null
          key?: string
          name?: string
          description?: string | null
          rank?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "roles_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      schedules: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          week_start: string
          status: string
          published_at: string | null
          published_by_person_id: string | null
          created_by_person_id: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          week_start: string
          status?: string
          published_at?: string | null
          published_by_person_id?: string | null
          created_by_person_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          week_start?: string
          status?: string
          published_at?: string | null
          published_by_person_id?: string | null
          created_by_person_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "schedules_created_by_person_id_organization_id_fkey"
            columns: ["created_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "schedules_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "schedules_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "schedules_published_by_person_id_organization_id_fkey"
            columns: ["published_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      shift_claims: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          shift_id: string
          person_id: string
          status: string
          decided_by_person_id: string | null
          decided_at: string | null
          auto_approved: boolean
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          shift_id: string
          person_id: string
          status?: string
          decided_by_person_id?: string | null
          decided_at?: string | null
          auto_approved?: boolean
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          shift_id?: string
          person_id?: string
          status?: string
          decided_by_person_id?: string | null
          decided_at?: string | null
          auto_approved?: boolean
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "shift_claims_decided_by_person_id_organization_id_fkey"
            columns: ["decided_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_claims_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_claims_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "shift_claims_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_claims_shift_id_organization_id_location_id_fkey"
            columns: ["shift_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "shifts"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      shift_swaps: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          kind: string
          shift_id: string
          counter_shift_id: string | null
          from_person_id: string
          to_person_id: string | null
          note: string | null
          status: string
          accepted_at: string | null
          decided_by_person_id: string | null
          decided_at: string | null
          auto_approved: boolean
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          kind: string
          shift_id: string
          counter_shift_id?: string | null
          from_person_id: string
          to_person_id?: string | null
          note?: string | null
          status?: string
          accepted_at?: string | null
          decided_by_person_id?: string | null
          decided_at?: string | null
          auto_approved?: boolean
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          kind?: string
          shift_id?: string
          counter_shift_id?: string | null
          from_person_id?: string
          to_person_id?: string | null
          note?: string | null
          status?: string
          accepted_at?: string | null
          decided_by_person_id?: string | null
          decided_at?: string | null
          auto_approved?: boolean
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "shift_swaps_counter_shift_id_organization_id_location_id_fkey"
            columns: ["counter_shift_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "shifts"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
          {
            foreignKeyName: "shift_swaps_decided_by_person_id_organization_id_fkey"
            columns: ["decided_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_swaps_from_person_id_organization_id_fkey"
            columns: ["from_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_swaps_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_swaps_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "shift_swaps_shift_id_organization_id_location_id_fkey"
            columns: ["shift_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "shifts"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
          {
            foreignKeyName: "shift_swaps_to_person_id_organization_id_fkey"
            columns: ["to_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      shift_template_items: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          template_id: string
          position_id: string
          day_offset: number
          start_time: string
          duration_minutes: number
          assigned_person_id: string | null
          notes: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          template_id: string
          position_id: string
          day_offset: number
          start_time: string
          duration_minutes: number
          assigned_person_id?: string | null
          notes?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          template_id?: string
          position_id?: string
          day_offset?: number
          start_time?: string
          duration_minutes?: number
          assigned_person_id?: string | null
          notes?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "shift_template_items_assigned_person_id_organization_id_fkey"
            columns: ["assigned_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_template_items_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_template_items_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "shift_template_items_position_id_organization_id_fkey"
            columns: ["position_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "positions"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_template_items_template_id_organization_id_location__fkey"
            columns: ["template_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "shift_templates"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      shift_templates: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          name: string
          span_days: number
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          name: string
          span_days?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          name?: string
          span_days?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "shift_templates_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shift_templates_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      shifts: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          schedule_id: string
          position_id: string
          starts_at: string
          ends_at: string
          assigned_person_id: string | null
          status: string
          notes: string | null
          created_by_person_id: string | null
          cancelled_at: string | null
          override_kinds: string[] | null
          override_by_person_id: string | null
          override_at: string | null
          uncovered_emitted_for: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          schedule_id: string
          position_id: string
          starts_at: string
          ends_at: string
          assigned_person_id?: string | null
          status?: string
          notes?: string | null
          created_by_person_id?: string | null
          cancelled_at?: string | null
          override_kinds?: string[] | null
          override_by_person_id?: string | null
          override_at?: string | null
          uncovered_emitted_for?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          schedule_id?: string
          position_id?: string
          starts_at?: string
          ends_at?: string
          assigned_person_id?: string | null
          status?: string
          notes?: string | null
          created_by_person_id?: string | null
          cancelled_at?: string | null
          override_kinds?: string[] | null
          override_by_person_id?: string | null
          override_at?: string | null
          uncovered_emitted_for?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "shifts_assigned_person_id_organization_id_fkey"
            columns: ["assigned_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shifts_created_by_person_id_organization_id_fkey"
            columns: ["created_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shifts_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shifts_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "shifts_override_by_person_id_organization_id_fkey"
            columns: ["override_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shifts_position_id_organization_id_fkey"
            columns: ["position_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "positions"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "shifts_schedule_id_organization_id_location_id_fkey"
            columns: ["schedule_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "schedules"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      space_closures: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          space_id: string | null
          starts_at: string
          ends_at: string
          reason: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          space_id?: string | null
          starts_at: string
          ends_at: string
          reason?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          space_id?: string | null
          starts_at?: string
          ends_at?: string
          reason?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "space_closures_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "space_closures_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "space_closures_space_id_organization_id_location_id_fkey"
            columns: ["space_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "spaces"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      space_hours: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          space_id: string
          day_of_week: number
          opens_at: string
          closes_at: string
          effective_from: string | null
          effective_to: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          space_id: string
          day_of_week: number
          opens_at: string
          closes_at: string
          effective_from?: string | null
          effective_to?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          space_id?: string
          day_of_week?: number
          opens_at?: string
          closes_at?: string
          effective_from?: string | null
          effective_to?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "space_hours_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "space_hours_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "space_hours_space_id_organization_id_location_id_fkey"
            columns: ["space_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "spaces"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      space_kinds: {
        Row: {
          id: string
          organization_id: string
          key: string
          name: string
          sort_order: number
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          key: string
          name: string
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          key?: string
          name?: string
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "space_kinds_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      spaces: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          space_kind_id: string
          parent_space_id: string | null
          name: string
          description: string | null
          capacity: number | null
          sort_order: number
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          space_kind_id: string
          parent_space_id?: string | null
          name: string
          description?: string | null
          capacity?: number | null
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          space_kind_id?: string
          parent_space_id?: string | null
          name?: string
          description?: string | null
          capacity?: number | null
          sort_order?: number
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "spaces_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "spaces_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "spaces_parent_space_id_organization_id_location_id_fkey"
            columns: ["parent_space_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "spaces"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
          {
            foreignKeyName: "spaces_space_kind_id_organization_id_fkey"
            columns: ["space_kind_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "space_kinds"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      task_events: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          task_id: string
          kind: string
          actor_person_id: string | null
          from_status: string | null
          to_status: string | null
          assigned_person_id: string | null
          assigned_job_title_id: string | null
          body: string | null
          source_event_id: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          task_id: string
          kind: string
          actor_person_id?: string | null
          from_status?: string | null
          to_status?: string | null
          assigned_person_id?: string | null
          assigned_job_title_id?: string | null
          body?: string | null
          source_event_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          task_id?: string
          kind?: string
          actor_person_id?: string | null
          from_status?: string | null
          to_status?: string | null
          assigned_person_id?: string | null
          assigned_job_title_id?: string | null
          body?: string | null
          source_event_id?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "task_events_actor_person_id_organization_id_fkey"
            columns: ["actor_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "task_events_assigned_job_title_id_organization_id_fkey"
            columns: ["assigned_job_title_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "job_titles"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "task_events_assigned_person_id_organization_id_fkey"
            columns: ["assigned_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "task_events_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "task_events_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "task_events_task_id_organization_id_location_id_fkey"
            columns: ["task_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "tasks"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
        ]
      }
      task_templates: {
        Row: {
          id: string
          organization_id: string
          location_id: string | null
          title: string
          instructions: string | null
          default_priority: string
          due_offset_minutes: number | null
          assign_to: string
          assign_job_title_id: string | null
          assign_person_id: string | null
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id?: string | null
          title: string
          instructions?: string | null
          default_priority?: string
          due_offset_minutes?: number | null
          assign_to?: string
          assign_job_title_id?: string | null
          assign_person_id?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string | null
          title?: string
          instructions?: string | null
          default_priority?: string
          due_offset_minutes?: number | null
          assign_to?: string
          assign_job_title_id?: string | null
          assign_person_id?: string | null
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "task_templates_assign_job_title_id_organization_id_fkey"
            columns: ["assign_job_title_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "job_titles"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "task_templates_assign_person_id_organization_id_fkey"
            columns: ["assign_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "task_templates_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "task_templates_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
        ]
      }
      tasks: {
        Row: {
          id: string
          organization_id: string
          location_id: string
          space_id: string | null
          title: string
          instructions: string | null
          status: string
          priority: string
          due_at: string | null
          assigned_person_id: string | null
          assigned_job_title_id: string | null
          created_by_person_id: string | null
          completed_by_person_id: string | null
          completed_at: string | null
          cancelled_at: string | null
          source_event_id: string | null
          source_rule_id: string | null
          task_template_id: string | null
          overdue_emitted_for: string | null
          created_at: string
          updated_at: string
          escalated_for: string | null
        }
        Insert: {
          id?: string
          organization_id: string
          location_id: string
          space_id?: string | null
          title: string
          instructions?: string | null
          status?: string
          priority?: string
          due_at?: string | null
          assigned_person_id?: string | null
          assigned_job_title_id?: string | null
          created_by_person_id?: string | null
          completed_by_person_id?: string | null
          completed_at?: string | null
          cancelled_at?: string | null
          source_event_id?: string | null
          source_rule_id?: string | null
          task_template_id?: string | null
          overdue_emitted_for?: string | null
          created_at?: string
          updated_at?: string
          escalated_for?: string | null
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string
          space_id?: string | null
          title?: string
          instructions?: string | null
          status?: string
          priority?: string
          due_at?: string | null
          assigned_person_id?: string | null
          assigned_job_title_id?: string | null
          created_by_person_id?: string | null
          completed_by_person_id?: string | null
          completed_at?: string | null
          cancelled_at?: string | null
          source_event_id?: string | null
          source_rule_id?: string | null
          task_template_id?: string | null
          overdue_emitted_for?: string | null
          created_at?: string
          updated_at?: string
          escalated_for?: string | null
        }
        Relationships: [
          {
            foreignKeyName: "tasks_assigned_job_title_id_organization_id_fkey"
            columns: ["assigned_job_title_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "job_titles"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "tasks_assigned_person_id_organization_id_fkey"
            columns: ["assigned_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "tasks_completed_by_person_id_organization_id_fkey"
            columns: ["completed_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "tasks_created_by_person_id_organization_id_fkey"
            columns: ["created_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "tasks_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "tasks_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "tasks_source_rule_id_organization_id_fkey"
            columns: ["source_rule_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "workflow_rules"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "tasks_space_id_organization_id_location_id_fkey"
            columns: ["space_id", "organization_id", "location_id"]
            isOneToOne: false
            referencedRelation: "spaces"
            referencedColumns: ["id", "organization_id", "location_id"]
          },
          {
            foreignKeyName: "tasks_task_template_id_organization_id_fkey"
            columns: ["task_template_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "task_templates"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      time_off_requests: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          starts_on: string
          ends_on: string
          reason: string | null
          status: string
          decided_by_person_id: string | null
          decided_at: string | null
          cancelled_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          starts_on: string
          ends_on: string
          reason?: string | null
          status?: string
          decided_by_person_id?: string | null
          decided_at?: string | null
          cancelled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          starts_on?: string
          ends_on?: string
          reason?: string | null
          status?: string
          decided_by_person_id?: string | null
          decided_at?: string | null
          cancelled_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "time_off_requests_decided_by_person_id_organization_id_fkey"
            columns: ["decided_by_person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "time_off_requests_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "time_off_requests_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      user_permissions: {
        Row: {
          id: string
          organization_id: string
          person_id: string
          location_id: string | null
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          person_id: string
          location_id?: string | null
          module_key: string
          level: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          person_id?: string
          location_id?: string | null
          module_key?: string
          level?: Database["public"]["Enums"]["permission_level"]
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "user_permissions_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "user_permissions_module_key_fkey"
            columns: ["module_key"]
            isOneToOne: false
            referencedRelation: "modules"
            referencedColumns: ["key"]
          },
          {
            foreignKeyName: "user_permissions_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "user_permissions_person_id_organization_id_fkey"
            columns: ["person_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "people"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
      workflow_rules: {
        Row: {
          id: string
          organization_id: string
          location_id: string | null
          name: string
          event_type: string
          condition: Json
          task_template_id: string
          enabled: boolean
          archived_at: string | null
          created_at: string
          updated_at: string
        }
        Insert: {
          id?: string
          organization_id: string
          location_id?: string | null
          name: string
          event_type: string
          condition?: Json
          task_template_id: string
          enabled?: boolean
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Update: {
          id?: string
          organization_id?: string
          location_id?: string | null
          name?: string
          event_type?: string
          condition?: Json
          task_template_id?: string
          enabled?: boolean
          archived_at?: string | null
          created_at?: string
          updated_at?: string
        }
        Relationships: [
          {
            foreignKeyName: "workflow_rules_location_id_organization_id_fkey"
            columns: ["location_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "locations"
            referencedColumns: ["id", "organization_id"]
          },
          {
            foreignKeyName: "workflow_rules_organization_id_fkey"
            columns: ["organization_id"]
            isOneToOne: false
            referencedRelation: "organizations"
            referencedColumns: ["id"]
          },
          {
            foreignKeyName: "workflow_rules_task_template_id_organization_id_fkey"
            columns: ["task_template_id", "organization_id"]
            isOneToOne: false
            referencedRelation: "task_templates"
            referencedColumns: ["id", "organization_id"]
          },
        ]
      }
    }
    Views: {
      [_ in never]: never
    }
    Functions: {
      is_platform_admin: {
        Args: never
        Returns: boolean
      }
      auth_org_ids: {
        Args: never
        Returns: string[]
      }
      auth_location_ids: {
        Args: never
        Returns: string[]
      }
      current_person_id: {
        Args: { p_organization_id: string }
        Returns: string | null
      }
      has_role: {
        Args: { p_organization_id: string; p_location_id: string | null; p_role_key: string }
        Returns: boolean
      }
      actor_rank: {
        Args: { p_organization_id: string; p_location_id: string | null }
        Returns: number
      }
      effective_permission: {
        Args: { p_organization_id: string; p_location_id: string | null; p_module_key: string }
        Returns: Database["public"]["Enums"]["permission_level"]
      }
      has_permission: {
        Args: { p_organization_id: string; p_location_id: string | null; p_module_key: string; p_min_level: Database["public"]["Enums"]["permission_level"] }
        Returns: boolean
      }
      create_person_with_assignment: {
        Args: { p_organization_id: string; p_first_name: string; p_last_name: string; p_role_id: string; p_location_id: string | null; p_preferred_name?: string | null; p_email?: string | null; p_phone?: string | null; p_employee_number?: string | null }
        Returns: string
      }
      update_own_profile: {
        Args: { p_organization_id: string; p_preferred_name: string | null; p_phone: string | null }
        Returns: string
      }
      person_effective_permission: {
        Args: { p_organization_id: string; p_person_id: string; p_location_id: string | null; p_module_key: string }
        Returns: Database["public"]["Enums"]["permission_level"]
      }
      replace_role_assignment: {
        Args: { p_assignment_id: string; p_role_id: string; p_location_id: string | null }
        Returns: string
      }
      session_needs_mfa: {
        Args: never
        Returns: boolean
      }
      consume_rate_limit: {
        Args: { p_bucket: string; p_key: string; p_max: number; p_window_seconds: number }
        Returns: boolean
      }
      can_manage_person_account: {
        Args: { p_organization_id: string; p_person_id: string }
        Returns: boolean
      }
      claim_outbox_events: {
        Args: { p_worker: string; p_limit: number; p_lock_seconds: number }
        Returns: Database["public"]["Tables"]["outbox_events"]["Row"][]
      }
      complete_outbox_event: {
        Args: { p_id: string; p_worker: string }
        Returns: boolean
      }
      fail_outbox_event: {
        Args: { p_id: string; p_worker: string; p_error: string }
        Returns: string | null
      }
      record_outbox_handler: {
        Args: { p_event_id: string; p_handler: string }
        Returns: boolean
      }
      outbox_handlers_done: {
        Args: { p_event_id: string }
        Returns: string[]
      }
      retry_dead_outbox_event: {
        Args: { p_id: string }
        Returns: undefined
      }
      create_task: {
        Args: { p_organization_id: string; p_location_id: string; p_title: string; p_instructions?: string | null; p_due_at?: string | null; p_priority?: string; p_space_id?: string | null; p_assigned_person_id?: string | null; p_assigned_job_title_id?: string | null }
        Returns: string
      }
      start_task: {
        Args: { p_task_id: string }
        Returns: undefined
      }
      complete_task: {
        Args: { p_task_id: string; p_note?: string | null }
        Returns: undefined
      }
      reopen_task: {
        Args: { p_task_id: string; p_reason?: string | null }
        Returns: undefined
      }
      assign_task: {
        Args: { p_task_id: string; p_person_id: string | null; p_job_title_id: string | null }
        Returns: undefined
      }
      cancel_task: {
        Args: { p_task_id: string; p_reason?: string | null }
        Returns: undefined
      }
      add_task_comment: {
        Args: { p_task_id: string; p_body: string }
        Returns: string
      }
      match_workflow_rules: {
        Args: { p_event_id: string }
        Returns: { rule_id: string; task_template_id: string }[]
      }
      create_task_from_event: {
        Args: { p_event_id: string; p_rule_id: string }
        Returns: string | null
      }
      emit_overdue_task_events: {
        Args: { p_limit?: number }
        Returns: number
      }
      publish_notice: {
        Args: { p_notice_id: string; p_publish_at?: string | null }
        Returns: undefined
      }
      archive_notice: {
        Args: { p_notice_id: string }
        Returns: undefined
      }
      acknowledge_notice: {
        Args: { p_notice_id: string }
        Returns: string
      }
      send_message: {
        Args: { p_organization_id: string; p_recipient_person_ids: string[]; p_body: string }
        Returns: string
      }
      mark_message_read: {
        Args: { p_message_id: string }
        Returns: undefined
      }
      create_notification: {
        Args: { p_event_id: string; p_person_id: string; p_kind: string; p_title: string; p_body?: string | null; p_link_path?: string | null; p_urgency?: string | null }
        Returns: string | null
      }
      notice_audience_person_ids: {
        Args: { p_notice_id: string }
        Returns: string[]
      }
      task_recipient_person_ids: {
        Args: { p_task_id: string }
        Returns: string[]
      }
      claim_notification_deliveries: {
        Args: { p_worker: string; p_limit: number; p_lock_seconds: number; p_channel?: string | null }
        Returns: Database["public"]["Tables"]["notification_deliveries"]["Row"][]
      }
      complete_notification_delivery: {
        Args: { p_id: string; p_worker: string; p_provider_message_id?: string | null }
        Returns: boolean
      }
      fail_notification_delivery: {
        Args: { p_id: string; p_worker: string; p_error: string; p_permanent?: boolean }
        Returns: string | null
      }
      skip_notification_delivery: {
        Args: { p_id: string; p_worker: string; p_reason: string }
        Returns: boolean
      }
      disable_push_subscription: {
        Args: { p_id: string }
        Returns: boolean
      }
      mark_notifications_read: {
        Args: { p_notification_ids: string[] }
        Returns: number
      }
      mark_all_notifications_read: {
        Args: { p_organization_id: string }
        Returns: number
      }
      save_push_subscription: {
        Args: { p_organization_id: string; p_endpoint: string; p_p256dh: string; p_auth_secret: string; p_user_agent?: string | null }
        Returns: string
      }
      delete_push_subscription: {
        Args: { p_organization_id: string; p_endpoint: string }
        Returns: boolean
      }
      release_outbox_event: {
        Args: { p_id: string; p_worker: string }
        Returns: boolean
      }
      extend_outbox_lock: {
        Args: { p_id: string; p_worker: string; p_seconds: number }
        Returns: boolean
      }
      release_notification_delivery: {
        Args: { p_id: string; p_worker: string }
        Returns: boolean
      }
      escalate_overdue_task: {
        Args: { p_event_id: string }
        Returns: string[]
      }
      notice_acknowledgment_status: {
        Args: { p_notice_id: string }
        Returns: { person_id: string; acknowledged_at: string | null }[]
      }
      my_notices: {
        Args: { p_organization_id?: string | null; p_limit?: number }
        Returns: { notice_id: string; organization_id: string; location_id: string | null; title: string; body: string; urgency: string; requires_acknowledgment: boolean; publish_at: string | null; expires_at: string | null; acknowledged_at: string | null }[]
      }
      create_notifications: {
        Args: { p_event_id: string; p_person_ids: string[]; p_kind: string; p_title: string; p_summary?: string | null; p_link?: string | null; p_urgency?: string | null }
        Returns: number
      }
      worker_task_for_event: {
        Args: { p_event_id: string }
        Returns: { task_id: string; organization_id: string; location_id: string; location_name: string; title: string; status: string; priority: string; due_at: string | null; assigned_person_id: string | null; assigned_job_title_id: string | null }[]
      }
      worker_notice_for_event: {
        Args: { p_event_id: string }
        Returns: { notice_id: string; organization_id: string; location_id: string | null; title: string; status: string; urgency: string; requires_acknowledgment: boolean; publish_at: string | null; expires_at: string | null }[]
      }
      worker_notification_for_delivery: {
        Args: { p_delivery_id: string }
        Returns: { delivery_id: string; notification_id: string; organization_id: string; person_id: string; channel: string; status: string; attempts: number; kind: string; title: string; body: string | null; link_path: string | null; urgency: string }[]
      }
      worker_email_for_delivery: {
        Args: { p_delivery_id: string }
        Returns: string | null
      }
      worker_push_subscriptions_for_delivery: {
        Args: { p_delivery_id: string }
        Returns: { subscription_id: string; endpoint: string; p256dh: string; auth_secret: string }[]
      }
      can_resend_person_invite: {
        Args: { p_organization_id: string; p_person_id: string }
        Returns: boolean
      }
      worker_message_recipients_for_event: {
        Args: { p_event_id: string }
        Returns: { organization_id: string; message_id: string; person_id: string; link_path: string }[]
      }
      save_position: {
        Args: { p_organization_id: string; p_location_id: string | null; p_name: string; p_qualification_ids?: string[] | null; p_position_id?: string | null }
        Returns: string
      }
      archive_position: {
        Args: { p_position_id: string; p_archived?: boolean }
        Returns: undefined
      }
      save_qualification: {
        Args: { p_organization_id: string; p_name: string; p_qualification_id?: string | null }
        Returns: string
      }
      archive_qualification: {
        Args: { p_qualification_id: string; p_archived?: boolean }
        Returns: undefined
      }
      set_person_qualification: {
        Args: { p_organization_id: string; p_person_id: string; p_qualification_id: string; p_valid_from?: string | null; p_expires_on?: string | null }
        Returns: string
      }
      remove_person_qualification: {
        Args: { p_person_qualification_id: string }
        Returns: undefined
      }
      save_shift_template: {
        Args: { p_organization_id: string; p_location_id: string; p_name: string; p_span_days?: number | null; p_template_id?: string | null }
        Returns: string
      }
      archive_shift_template: {
        Args: { p_template_id: string; p_archived?: boolean }
        Returns: undefined
      }
      add_shift_template_item: {
        Args: { p_template_id: string; p_position_id: string; p_day_offset: number; p_start_time: string; p_duration_minutes: number; p_assigned_person_id?: string | null; p_notes?: string | null }
        Returns: string
      }
      remove_shift_template_item: {
        Args: { p_item_id: string }
        Returns: undefined
      }
      create_schedule: {
        Args: { p_organization_id: string; p_location_id: string; p_week_start: string }
        Returns: string
      }
      publish_schedule: {
        Args: { p_schedule_id: string }
        Returns: undefined
      }
      create_shift: {
        Args: { p_schedule_id: string; p_position_id: string; p_starts_at: string; p_ends_at: string; p_assigned_person_id?: string | null; p_notes?: string | null; p_override?: boolean }
        Returns: string
      }
      update_shift: {
        Args: { p_shift_id: string; p_position_id?: string | null; p_starts_at?: string | null; p_ends_at?: string | null; p_notes?: string | null; p_override?: boolean }
        Returns: undefined
      }
      assign_shift: {
        Args: { p_shift_id: string; p_person_id: string | null; p_override?: boolean }
        Returns: undefined
      }
      cancel_shift: {
        Args: { p_shift_id: string }
        Returns: undefined
      }
      request_shift_swap: {
        Args: { p_shift_id: string; p_to_person_id: string; p_counter_shift_id?: string | null; p_note?: string | null }
        Returns: string
      }
      respond_shift_swap: {
        Args: { p_swap_id: string; p_accept: boolean }
        Returns: string
      }
      decide_shift_swap: {
        Args: { p_swap_id: string; p_approve: boolean; p_override?: boolean }
        Returns: undefined
      }
      cancel_shift_swap: {
        Args: { p_swap_id: string }
        Returns: undefined
      }
      request_shift_drop: {
        Args: { p_shift_id: string; p_note?: string | null }
        Returns: string
      }
      request_shift_claim: {
        Args: { p_shift_id: string }
        Returns: string
      }
      decide_shift_claim: {
        Args: { p_claim_id: string; p_approve: boolean; p_override?: boolean }
        Returns: undefined
      }
      cancel_shift_claim: {
        Args: { p_claim_id: string }
        Returns: undefined
      }
      my_claimable_shifts: {
        Args: { p_organization_id: string; p_limit?: number }
        Returns: { shift_id: string; location_id: string; schedule_id: string; position_id: string; starts_at: string; ends_at: string }[]
      }
      add_availability: {
        Args: { p_organization_id: string; p_day_of_week: number; p_start_time: string; p_end_time: string; p_kind: string; p_effective_from?: string | null; p_effective_to?: string | null }
        Returns: string
      }
      remove_availability: {
        Args: { p_availability_id: string }
        Returns: undefined
      }
      request_time_off: {
        Args: { p_organization_id: string; p_starts_on: string; p_ends_on: string; p_reason?: string | null }
        Returns: string
      }
      cancel_time_off: {
        Args: { p_time_off_id: string }
        Returns: undefined
      }
      decide_time_off: {
        Args: { p_time_off_id: string; p_approve: boolean }
        Returns: undefined
      }
      emit_uncovered_shift_events: {
        Args: { p_within: string; p_limit?: number }
        Returns: number
      }
      worker_shift_for_event: {
        Args: { p_event_id: string }
        Returns: { shift_id: string; organization_id: string; location_id: string; location_name: string; location_timezone: string; schedule_id: string; schedule_status: string; week_start: string; position_id: string; position_name: string; starts_at: string; ends_at: string; assigned_person_id: string | null; status: string }[]
      }
      worker_shift_event_recipients: {
        Args: { p_event_id: string }
        Returns: { person_id: string; reason: string }[]
      }
      shift_overrides: {
        Args: { p_schedule_id: string }
        Returns: { shift_id: string; override_kinds: string[]; override_by_person_id: string; override_at: string }[]
      }
      position_shifts_missing_qualification: {
        Args: { p_position_id: string }
        Returns: number
      }
      apply_shift_template: {
        Args: { p_schedule_id: string; p_template_id: string; p_first_day?: number }
        Returns: { shift_id: string | null; assigned_person_id: string | null; refused: string | null; item_id: string }[]
      }
      swap_candidates: {
        Args: { p_shift_id: string }
        Returns: { person_id: string; display_name: string }[]
      }
      set_staffing_switches: {
        Args: { p_organization_id: string; p_auto_approve_swaps?: boolean | null; p_first_come_open_shifts?: boolean | null }
        Returns: undefined
      }
    }
    Enums: {
      permission_level: "none" | "view" | "edit" | "admin"
    }
    CompositeTypes: {
      [_ in never]: never
    }
  }
}

type DefaultSchema = Database["public"]

export type Tables<
  DefaultSchemaTableNameOrOptions extends
    | keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
    ? keyof (Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
        Database[DefaultSchemaTableNameOrOptions["schema"]]["Views"])
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? (Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"] &
      Database[DefaultSchemaTableNameOrOptions["schema"]]["Views"])[TableName] extends {
      Row: infer R
    }
    ? R
    : never
  : DefaultSchemaTableNameOrOptions extends keyof (DefaultSchema["Tables"] & DefaultSchema["Views"])
    ? (DefaultSchema["Tables"] & DefaultSchema["Views"])[DefaultSchemaTableNameOrOptions] extends {
        Row: infer R
      }
      ? R
      : never
    : never

export type TablesInsert<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Insert: infer I
    }
    ? I
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Insert: infer I
      }
      ? I
      : never
    : never

export type TablesUpdate<
  DefaultSchemaTableNameOrOptions extends
    | keyof DefaultSchema["Tables"]
    | { schema: keyof Database },
  TableName extends DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
    ? keyof Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"]
    : never = never,
> = DefaultSchemaTableNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaTableNameOrOptions["schema"]]["Tables"][TableName] extends {
      Update: infer U
    }
    ? U
    : never
  : DefaultSchemaTableNameOrOptions extends keyof DefaultSchema["Tables"]
    ? DefaultSchema["Tables"][DefaultSchemaTableNameOrOptions] extends {
        Update: infer U
      }
      ? U
      : never
    : never

export type Enums<
  DefaultSchemaEnumNameOrOptions extends
    | keyof DefaultSchema["Enums"]
    | { schema: keyof Database },
  EnumName extends DefaultSchemaEnumNameOrOptions extends { schema: keyof Database }
    ? keyof Database[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"]
    : never = never,
> = DefaultSchemaEnumNameOrOptions extends { schema: keyof Database }
  ? Database[DefaultSchemaEnumNameOrOptions["schema"]]["Enums"][EnumName]
  : DefaultSchemaEnumNameOrOptions extends keyof DefaultSchema["Enums"]
    ? DefaultSchema["Enums"][DefaultSchemaEnumNameOrOptions]
    : never

export type CompositeTypes<
  PublicCompositeTypeNameOrOptions extends
    | keyof DefaultSchema["CompositeTypes"]
    | { schema: keyof Database },
  CompositeTypeName extends PublicCompositeTypeNameOrOptions extends { schema: keyof Database }
    ? keyof Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"]
    : never = never,
> = PublicCompositeTypeNameOrOptions extends { schema: keyof Database }
  ? Database[PublicCompositeTypeNameOrOptions["schema"]]["CompositeTypes"][CompositeTypeName]
  : PublicCompositeTypeNameOrOptions extends keyof DefaultSchema["CompositeTypes"]
    ? DefaultSchema["CompositeTypes"][PublicCompositeTypeNameOrOptions]
    : never

export const Constants = {
  public: {
    Enums: {
      permission_level: ["none", "view", "edit", "admin"],
    },
  },
} as const
